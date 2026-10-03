"""
OSV records -> DistroVuln rows, and the OSV.dev download service.

The distributions publish their advisories in the OSV format (Canonical:
USN and UBUNTU-CVE records; Debian: DSA/DLA and CVE records; Red Hat:
RHSA; Rocky: RLSA; AlmaLinux: ALSA), and OSV.dev serves them as one ZIP per
ecosystem plus a list of what changed when:

  <base>/<ecosystem>/all.zip            every record
  <base>/<ecosystem>/modified_id.csv    "<modified>,<id>", newest first
  <base>/<ecosystem>/<id>.json          one record

The parser is pure, so it is tested on captured records. OSV_BASE_URL points
it at a mirror.
"""
import io
import json
import logging
import math
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import quote

import requests

from app.models.advisory import AVAILABILITY_PRO, AVAILABILITY_STANDARD, KIND_ADVISORY, KIND_CVE
from app.modules.advisories import releases

logger = logging.getLogger(__name__)

OSV_BASE_URL = (os.getenv("OSV_BASE_URL") or "https://osv-vulnerabilities.storage.googleapis.com").rstrip("/")
TIMEOUT = 60
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_ZIP_BYTES = int(os.getenv("OSV_MAX_ZIP_MB") or "4096") * 1024 * 1024
FETCH_WORKERS = 8

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ADVISORY = re.compile(r"^(USN|DSA|DLA|DTSA|RHSA|RHBA|RHEA|RLSA|RLBA|RLEA|RXSA|ALSA|ALBA|ALEA)-")
_NOT_SECURITY = re.compile(r"^(RHBA|RHEA|RLBA|RLEA|ALBA|ALEA)-")
_RPM_SKIP = re.compile(r"-(debuginfo|debugsource)$")
# Ubuntu and Debian track every kernel CVE per kernel flavour (linux-aws,
# linux-gcp, ... about 40), most of them with no fix: thousands of rows per
# release that say nothing an admin can act on. Kernel rows are kept only
# when they carry a fix.
_KERNEL_SOURCE = re.compile(r"^linux(-|$)")
_SEV_WORD = {"critical": "critical", "important": "high", "high": "high", "moderate": "medium",
             "medium": "medium", "low": "low", "negligible": "low"}


from app.modules.cve.feeds import FeedError  # noqa: E402 - one error type for every download job


# ── CVSS v3 base score (for severity when the CVE is not in NVD here) ─────

_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["C"][m["I"]]) * (1 - _W["C"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = 1.08 * (impact + exploit) if scope_changed else impact + exploit
        return _roundup(min(raw, 10))
    except (KeyError, ValueError, IndexError):
        return None


def severity_of_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 \
        else None


# ── parsing ──────────────────────────────────────────────────────────────

def _dt(value) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None, microsecond=0)
    except ValueError:
        return None


def _intervals(ranges) -> List[Tuple[Optional[str], Optional[str], Optional[str]]]:
    """(introduced, fixed, last_affected) per affected interval of the
    ECOSYSTEM ranges. introduced None = from the first version; fixed and
    last_affected both None = no fix yet."""
    out = []
    for r in ranges or []:
        if not isinstance(r, dict) or r.get("type") != "ECOSYSTEM":
            continue
        start, open_ = None, False
        for e in r.get("events") or []:
            if not isinstance(e, dict):
                continue
            if "introduced" in e:
                v = str(e["introduced"])
                start, open_ = (None if v == "0" else v[:160]), True
            elif "fixed" in e and open_:
                out.append((start, str(e["fixed"])[:160], None))
                open_ = False
            elif "last_affected" in e and open_:
                out.append((start, None, str(e["last_affected"])[:160]))
                open_ = False
        if open_:
            out.append((start, None, None))
    return out


def _record_severity(rec: dict) -> Optional[str]:
    m = re.match(r"^\s*(Critical|Important|Moderate|Low)\s*:", rec.get("summary") or "", re.I)
    if m:
        return _SEV_WORD[m.group(1).lower()]
    for s in rec.get("severity") or []:
        if isinstance(s, dict) and str(s.get("type", "")).startswith("CVSS_V3"):
            sev = severity_of_score(cvss3_score(str(s.get("score", ""))))
            if sev:
                return sev
    return None


def rows_from(rec: dict, wanted: Optional[Set[str]] = None) -> List[dict]:
    """DistroVuln rows (as dicts) of one OSV record, for the releases in
    `wanted` (every supported release when None)."""
    if not isinstance(rec, dict):
        return []
    rid = str(rec.get("id") or "")[:80]
    if not rid or rec.get("withdrawn"):
        return []
    if _ADVISORY.match(rid):
        kind = KIND_ADVISORY
        ids = [rid] + list(rec.get("upstream") or []) + list(rec.get("aliases") or []) + list(rec.get("related") or [])
        cves = sorted({x for x in ids if isinstance(x, str) and _CVE.match(x)})
        if _NOT_SECURITY.match(rid) and not cves:
            return []
    else:
        m = re.search(r"CVE-\d{4}-\d{4,}", rid)
        if not m:
            return []
        kind, cves = KIND_CVE, [m.group(0)]
    title = (rec.get("summary") or (rec.get("details") or "").strip().split("\n")[0] or "")[:300] or None
    base_sev = _record_severity(rec)
    published, modified = _dt(rec.get("published")), _dt(rec.get("modified"))

    rows, seen = [], set()
    for a in rec.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        found = releases.from_ecosystem(str(pkg.get("ecosystem") or ""))
        name = str(pkg.get("name") or "")[:200]
        if not found or not name:
            continue
        release, pro = found
        if wanted is not None and release not in wanted:
            continue
        if releases.family(release) == "rpm" and _RPM_SKIP.search(name):
            continue
        es = a.get("ecosystem_specific") if isinstance(a.get("ecosystem_specific"), dict) else {}
        sev = _SEV_WORD.get(str(es.get("ubuntu_priority") or "").lower()) or base_sev
        kernel = releases.family(release) == "deb" and _KERNEL_SOURCE.match(name)
        for introduced, fixed, last in _intervals(a.get("ranges")):
            if kernel and fixed is None and last is None:
                continue
            key = (release, pkg.get("ecosystem"), name, introduced, fixed, last)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"release": release, "stream": str(pkg.get("ecosystem"))[:80], "package": name,
                         "record_id": rid, "kind": kind, "introduced": introduced, "fixed": fixed,
                         "last_affected": last, "cves": cves, "severity": sev,
                         "availability": AVAILABILITY_PRO if pro else AVAILABILITY_STANDARD, "title": title,
                         "published": published, "modified": modified})
    return rows


def releases_in(rec: dict) -> Set[str]:
    out = set()
    for a in (rec.get("affected") or []) if isinstance(rec, dict) else []:
        if isinstance(a, dict):
            found = releases.from_ecosystem(str((a.get("package") or {}).get("ecosystem") or ""))
            if found:
                out.add(found[0])
    return out


def iter_zip(path: str) -> Iterator[dict]:
    """Every record of an OSV all.zip (or a ZIP of OSV JSON files)."""
    if os.path.getsize(path) > MAX_ZIP_BYTES:
        raise FeedError("The file is larger than allowed.")
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise FeedError("Not an OSV archive (not a valid ZIP file).") from exc
    with zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.file_size > MAX_RECORD_BYTES:
                continue
            try:
                rec = json.loads(zf.read(info))
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield rec


# ── download ─────────────────────────────────────────────────────────────

class OsvClient:
    def __init__(self, session: Optional[requests.Session] = None, base: str = OSV_BASE_URL):
        self.s = session or requests.Session()
        self.base = base

    def _url(self, ecosystem: str, name: str) -> str:
        return f"{self.base}/{quote(ecosystem)}/{quote(name)}"

    def download(self, ecosystem: str, dest: str, on_progress: Optional[Callable[[int, int], None]] = None,
                 cancelled: Callable[[], bool] = lambda: False) -> bool:
        """all.zip of an ecosystem into `dest`. False when OSV has none."""
        url = self._url(ecosystem, "all.zip")
        try:
            with self.s.get(url, timeout=TIMEOUT, stream=True) as resp:
                if resp.status_code == 404:
                    return False
                if resp.status_code != 200:
                    raise FeedError(f"OSV answered HTTP {resp.status_code} for {ecosystem}")
                total = int(resp.headers.get("content-length") or 0)
                done = 0
                with open(dest, "wb") as fh:
                    for chunk in resp.iter_content(1024 * 1024):
                        if cancelled():
                            raise FeedError("Cancelled")
                        fh.write(chunk)
                        done += len(chunk)
                        if done > MAX_ZIP_BYTES:
                            raise FeedError("The OSV archive is larger than allowed.")
                        if on_progress:
                            on_progress(done, total)
            return True
        except requests.RequestException as exc:
            raise FeedError(f"OSV.dev is not reachable: {exc.__class__.__name__}") from exc

    def changed_since(self, ecosystem: str, since: datetime, limit: int) -> Optional[List[Tuple[datetime, str]]]:
        """(modified, id) of the records changed after `since`, oldest first;
        None when there are more than `limit` (a full load is then cheaper)."""
        try:
            resp = self.s.get(self._url(ecosystem, "modified_id.csv"), timeout=TIMEOUT, stream=True)
        except requests.RequestException as exc:
            raise FeedError(f"OSV.dev is not reachable: {exc.__class__.__name__}") from exc
        with resp:
            if resp.status_code != 200:
                raise FeedError(f"OSV answered HTTP {resp.status_code} for the change list of {ecosystem}")
            out = []
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
                stamp, _, rid = line.partition(",")
                when = _dt(stamp)
                if when is None:
                    continue
                if when <= since:
                    break            # newest first: the rest is older
                out.append((when, rid.strip()))
                if len(out) > limit:
                    return None
        return list(reversed(out))

    def record(self, ecosystem: str, rid: str) -> Optional[dict]:
        try:
            resp = self.s.get(self._url(ecosystem, f"{rid}.json"), timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise FeedError(f"OSV.dev is not reachable: {exc.__class__.__name__}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code != 200 or len(resp.content) > MAX_RECORD_BYTES:
            raise FeedError(f"OSV answered HTTP {resp.status_code} for {rid}")
        try:
            return resp.json()
        except ValueError:
            return None

    def records(self, ecosystem: str, ids: Iterable[str], cancelled: Callable[[], bool] = lambda: False,
                on_progress: Optional[Callable[[int], None]] = None) -> Iterator[Tuple[str, Optional[dict]]]:
        ids = list(ids)
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            for n, (rid, rec) in enumerate(zip(ids, pool.map(lambda i: self.record(ecosystem, i), ids)), 1):
                if cancelled():
                    raise FeedError("Cancelled")
                if on_progress:
                    on_progress(n)
                yield rid, rec
