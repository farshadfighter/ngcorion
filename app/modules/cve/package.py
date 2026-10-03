"""
Offline update packages (.ngcve).

A package is a ZIP with exactly these members:

  manifest.json    what it holds and the SHA-256 of every other member
  manifest.sig     Ed25519 signature of manifest.json (keys.py)
  cves.jsonl.gz    normalised CVE records (feeds.normalize_nvd_cve), one per line
  kev.json         the full CISA KEV list (feeds.parse_kev output)
  epss.csv.gz      cve,epss,percentile for every scored CVE
  advisories.jsonl.gz  (optional) the distributions' advisories this
                   instance holds, one DistroVuln row per line; always
                   complete per release (manifest "advisories" names them)

kind "full" replaces nothing on its own - like an online update it upserts
every record - but it covers everything up to `until`, so it can load an
empty database. kind "delta" holds the CVEs NVD changed in [since, until].

Nothing is trusted before the signature checks out: the manifest is read
only as bytes to verify, and members are hashed against it before parsing.
Sizes are bounded (MAX_PACKAGE_BYTES / MAX_MEMBER_BYTES) against zip bombs.
"""
import gzip
import hashlib
import io
import json
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterator, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cve import CveCpeMatch, CveEntry
from app.modules.cve import keys, settings
from app.modules.cve.feeds import iso_to_dt

FORMAT = 1
MEMBERS = ("manifest.json", "manifest.sig", "cves.jsonl.gz", "kev.json", "epss.csv.gz")
OPTIONAL = ("advisories.jsonl.gz",)
MAX_PACKAGE_BYTES = int(os.getenv("CVE_MAX_PACKAGE_MB") or "2048") * 1024 * 1024
MAX_MEMBER_BYTES = 6 * 1024 * 1024 * 1024
EXTENSION = ".ngcve"


class PackageError(ValueError):
    pass


@dataclass
class Check:
    name: str
    status: str      # ok | warn | fail
    detail: str


@dataclass
class Verified:
    manifest: dict
    signer: str
    checks: List[Check] = field(default_factory=list)

    @property
    def importable(self) -> bool:
        return all(c.status != "fail" for c in self.checks)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── export ───────────────────────────────────────────────────────────────

def _record(e: CveEntry, cpes: List[CveCpeMatch]) -> dict:
    return {
        "id": e.cve_id,
        "published": e.published.isoformat() if e.published else None,
        "modified": e.last_modified.isoformat() if e.last_modified else None,
        "status": e.status, "description": e.description,
        "cvss": {"score": e.cvss_score, "version": e.cvss_version, "severity": e.severity, "vector": e.cvss_vector},
        "cwe": e.cwe, "refs": e.references or [],
        "cpes": [{"part": c.part, "vendor": c.vendor, "product": c.product, "version": c.version,
                  "start_incl": c.start_incl, "start_excl": c.start_excl, "end_incl": c.end_incl,
                  "end_excl": c.end_excl} for c in cpes],
    }


def build(db: Session, path: str, kind: str, since: Optional[datetime] = None,
          on_progress: Optional[Callable[[int, int], None]] = None) -> dict:
    """Write a signed package of this database to `path`. Returns the manifest."""
    until = iso_to_dt(settings.get(db, settings.WATERMARK))
    if until is None:
        raise PackageError("The CVE database has not been loaded yet - there is nothing to export.")
    q = select(CveEntry).order_by(CveEntry.cve_id)
    if kind == "delta":
        if since is None:
            raise PackageError("A delta package needs a start date.")
        q = q.where(CveEntry.last_modified >= since)
    total = db.query(CveEntry).count() if kind == "full" else db.query(CveEntry).filter(CveEntry.last_modified >= since).count()

    cves_buf = io.BytesIO()
    written = 0
    kev_items = []
    with gzip.GzipFile(fileobj=cves_buf, mode="wb", mtime=0) as gz:
        batch = []
        for e in db.scalars(q).yield_per(2000):
            batch.append(e)
            if len(batch) >= 2000:
                written += _write_batch(db, gz, batch)
                batch = []
                if on_progress:
                    on_progress(written, total)
        written += _write_batch(db, gz, batch)
    for e in db.scalars(select(CveEntry).where(CveEntry.kev.is_(True)).order_by(CveEntry.cve_id)):
        kev_items.append({"id": e.cve_id, "added": e.kev_added.isoformat() if e.kev_added else None,
                          "due": e.kev_due.isoformat() if e.kev_due else None,
                          "ransomware": e.kev_ransomware, "action": e.kev_action})
    kev_info = settings.get(db, settings.KEV_INFO) or {}
    kev_bytes = json.dumps({"version": kev_info.get("version"), "released": kev_info.get("released"),
                            "items": kev_items}).encode()

    epss_buf = io.BytesIO()
    epss_count = 0
    with gzip.GzipFile(fileobj=epss_buf, mode="wb", mtime=0) as gz:
        gz.write(f"#score_date:{settings.get(db, settings.EPSS_DATE) or ''}\ncve,epss,percentile\n".encode())
        for cve_id, score, pct in db.execute(select(CveEntry.cve_id, CveEntry.epss, CveEntry.epss_percentile)
                                             .where(CveEntry.epss.isnot(None)).order_by(CveEntry.cve_id)):
            gz.write(f"{cve_id},{score},{pct}\n".encode())
            epss_count += 1

    members = {"cves.jsonl.gz": cves_buf.getvalue(), "kev.json": kev_bytes, "epss.csv.gz": epss_buf.getvalue()}
    adv_bytes, adv_info = _advisories(db)
    if adv_info:
        members["advisories.jsonl.gz"] = adv_bytes
    public = keys.instance_public(db)
    manifest = {
        "format": FORMAT, "kind": kind,
        "created_at": datetime.utcnow().replace(microsecond=0).isoformat(),
        "instance": settings.get(db, settings.INSTANCE_NAME) or "NGCorion",
        "since": since.isoformat() if since else None, "until": until.isoformat(),
        "counts": {"cves": written, "kev": len(kev_items), "epss": epss_count},
        "kev": {"version": kev_info.get("version"), "released": kev_info.get("released")},
        "epss_date": settings.get(db, settings.EPSS_DATE),
        "files": {name: {"sha256": _sha(data), "size": len(data)} for name, data in members.items()},
        "key_fingerprint": keys.fingerprint(public),
    }
    if adv_info:
        manifest["advisories"] = adv_info
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("manifest.sig", keys.sign(db, manifest_bytes))
        for name, data in members.items():
            zf.writestr(name, data)
    return manifest


def _advisories(db: Session):
    """(gzip bytes, {release: {"watermark", "rows"}}) of every loaded release."""
    from app.models.advisory import DistroFeed, DistroVuln
    feeds = [f for f in db.query(DistroFeed).order_by(DistroFeed.release) if f.watermark and f.rows]
    if not feeds:
        return b"", {}
    buf = io.BytesIO()
    cols = ("release", "stream", "package", "record_id", "kind", "introduced", "fixed", "last_affected", "cves",
            "severity", "availability", "title", "published", "modified")
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        for f in feeds:
            q = select(*[getattr(DistroVuln, c) for c in cols]).where(DistroVuln.release == f.release)
            for row in db.execute(q.order_by(DistroVuln.id)).yield_per(5000):
                rec = dict(zip(cols, row))
                for c in ("published", "modified"):
                    rec[c] = rec[c].isoformat() if rec[c] else None
                gz.write((json.dumps(rec, separators=(",", ":")) + "\n").encode())
    info = {f.release: {"watermark": f.watermark.isoformat(), "rows": f.rows} for f in feeds}
    return buf.getvalue(), info


def _write_batch(db: Session, gz, batch: List[CveEntry]) -> int:
    if not batch:
        return 0
    ids = [e.cve_id for e in batch]
    cpes = {}
    for c in db.scalars(select(CveCpeMatch).where(CveCpeMatch.cve_id.in_(ids))):
        cpes.setdefault(c.cve_id, []).append(c)
    for e in batch:
        gz.write((json.dumps(_record(e, cpes.get(e.cve_id, [])), separators=(",", ":")) + "\n").encode())
    return len(batch)


# ── verify / read ────────────────────────────────────────────────────────

def _open(path: str) -> zipfile.ZipFile:
    if os.path.getsize(path) > MAX_PACKAGE_BYTES:
        raise PackageError("The file is larger than the allowed package size.")
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise PackageError("Not an NGCorion update package (not a valid archive).") from exc
    names = set(zf.namelist())
    if not set(MEMBERS) <= names or names - set(MEMBERS) - set(OPTIONAL):
        zf.close()
        raise PackageError("Not an NGCorion update package (unexpected contents).")
    for info in zf.infolist():
        if info.file_size > MAX_MEMBER_BYTES:
            zf.close()
            raise PackageError("The package contents are larger than allowed.")
    return zf


def verify(db: Session, path: str) -> Verified:
    """Signature, integrity and fit with this database. Raises PackageError
    when the file cannot be a package at all; otherwise returns the checks
    (any "fail" makes it non-importable)."""
    with _open(path) as zf:
        manifest_bytes = zf.read("manifest.json")
        signature = zf.read("manifest.sig").decode("ascii", "replace").strip()
        try:
            manifest = json.loads(manifest_bytes)
        except ValueError as exc:
            raise PackageError("The package manifest is unreadable.") from exc
        if not isinstance(manifest, dict):
            raise PackageError("The package manifest is unreadable.")

        checks: List[Check] = []
        signer = keys.verify(db, manifest_bytes, signature, str(manifest.get("key_fingerprint", "")))
        if signer:
            checks.append(Check("signature", "ok", f"Signed by a trusted key: {signer}"))
        else:
            checks.append(Check("signature", "fail",
                                "Not signed by a trusted key. Add the exporting NGCorion's key under "
                                "Trusted keys, or the package was changed after signing."))
            return Verified(manifest, "", checks)

        intact = True
        for name, meta in (manifest.get("files") or {}).items():
            if name not in MEMBERS + OPTIONAL or _sha(zf.read(name)) != meta.get("sha256"):
                intact = False
        checks.append(Check("integrity", "ok" if intact else "fail",
                            "Every file matches the signed manifest" if intact else
                            "The contents do not match the signed manifest"))

        checks.append(Check("format", "ok" if manifest.get("format") == FORMAT else "fail",
                            f"Package format v{manifest.get('format')}"))

        current = iso_to_dt(settings.get(db, settings.WATERMARK))
        until = iso_to_dt(manifest.get("until"))
        since = iso_to_dt(manifest.get("since"))
        if manifest.get("kind") == "full":
            if current and until and until <= current:
                checks.append(Check("freshness", "warn", "Not newer than this database - importing changes nothing new."))
            else:
                checks.append(Check("freshness", "ok", "Complete database"))
        elif current is None:
            checks.append(Check("freshness", "fail",
                                "This is a partial update, but the database is empty. Load the full database first."))
        elif since and since > current:
            checks.append(Check("freshness", "fail",
                                f"The package starts at {since:%d %b %Y %H:%M}, after this database ends "
                                f"({current:%d %b %Y %H:%M}) - changes in between would be missed."))
        elif until and until <= current:
            checks.append(Check("freshness", "warn", "Not newer than this database - importing changes nothing new."))
        else:
            checks.append(Check("freshness", "ok", f"Newer than this database ({current:%d %b %Y %H:%M})"))
        return Verified(manifest, signer, checks)


def read_cves(path: str) -> Iterator[dict]:
    with _open(path) as zf, zf.open("cves.jsonl.gz") as raw, gzip.open(raw, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rec = json.loads(line)
                if not isinstance(rec, dict) or "id" not in rec:
                    raise PackageError("The package holds a malformed CVE record.")
                rec.setdefault("cvss", {})
                yield rec


def read_advisories(path: str) -> Iterator[dict]:
    with _open(path) as zf:
        if "advisories.jsonl.gz" not in zf.namelist():
            return
        with zf.open("advisories.jsonl.gz") as raw, gzip.open(raw, "rt", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    if not isinstance(rec, dict) or "release" not in rec:
                        raise PackageError("The package holds a malformed advisory record.")
                    yield rec


def read_kev(path: str) -> dict:
    with _open(path) as zf:
        return json.loads(zf.read("kev.json"))


def read_epss(path: str) -> dict:
    from app.modules.cve.feeds import parse_epss_csv
    with _open(path) as zf:
        return parse_epss_csv(gzip.decompress(zf.read("epss.csv.gz")).decode("utf-8"))
