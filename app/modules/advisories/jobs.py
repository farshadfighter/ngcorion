"""
Loading and updating the advisories - the bodies of two CveUpdateJob kinds,
run by app/modules/cve/jobs.py like every other database job (one at a time,
in the background, one transaction, cancellable):

  advisories   online, from OSV.dev. A release never loaded is loaded in
               full (its distribution's all.zip); a loaded one takes only the records
               changed since its watermark, or everything again when more
               than INCREMENTAL_LIMIT changed.
  adv_import   an OSV all.zip an admin downloaded and uploaded (air-gapped
               sites). Every release in the file that this instance keeps is
               replaced - or, when it keeps none of them, every release in
               the file. The file is not signed; only admins may import it.

Signed .ngcve packages carry the advisories too (app/modules/cve/package.py).
"""
import hashlib
import logging
import os
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Set

from sqlalchemy.orm import Session

from app.models.advisory import DistroFeed
from app.modules.advisories import osv, releases, store

logger = logging.getLogger(__name__)

INCREMENTAL_LIMIT = int(os.getenv("OSV_INCREMENTAL_LIMIT") or "20000")


def make_client() -> osv.OsvClient:
    return osv.OsvClient()


class _Loader:
    """Inserts rows in batches, without duplicates, counting per release."""

    def __init__(self, db: Session, check: Callable[[], None]):
        self.db, self.check = db, check
        self.batch: List[dict] = []
        self.seen: Set[int] = set()
        self.records: Dict[str, Set[str]] = defaultdict(set)
        self.watermark: Dict[str, Optional[object]] = {}
        self.written = 0

    def add(self, rows: List[dict]) -> None:
        for r in rows:
            key = hash((r["release"], r["stream"], r["package"], r["record_id"], r["introduced"], r["fixed"],
                        r["last_affected"]))
            if key in self.seen:
                continue
            self.seen.add(key)
            self.batch.append(r)
            self.records[r["release"]].add(r["record_id"])
            m = r.get("modified")
            if m and (self.watermark.get(r["release"]) is None or m > self.watermark[r["release"]]):
                self.watermark[r["release"]] = m
        if len(self.batch) >= store.BATCH:
            self.flush()

    def flush(self) -> None:
        if self.batch:
            self.check()
            self.written += store.insert_rows(self.db, self.batch)
            self.batch = []


def _load_zip(loader: _Loader, path: str, wanted: Set[str], on_record: Optional[Callable[[int], None]] = None):
    for n, rec in enumerate(osv.iter_zip(path), 1):
        loader.add(osv.rows_from(rec, wanted))
        if on_record and n % 500 == 0:
            loader.check()
            on_record(n)
    loader.flush()


# ── online ───────────────────────────────────────────────────────────────

def online(j, db: Session, spool_dir: str) -> None:
    j.progress("connect", force=True)
    wanted = sorted(store.tracked(db))
    j.stats.update({"releases": wanted, "loaded": [], "updated": [], "records": 0, "rows": 0})
    if not wanted:
        j.stats["note"] = "No asset runs a supported Linux release yet - nothing to load."
        return
    client = make_client()
    feeds = {f.release: f for f in db.query(DistroFeed)}
    by_top: Dict[str, List[str]] = defaultdict(list)
    for r in wanted:
        by_top[releases.osv_top(r)].append(r)

    for top, rels in by_top.items():
        full = [r for r in rels if r not in feeds or feeds[r].watermark is None]
        inc = [r for r in rels if r not in full]
        if inc:
            since = min(feeds[r].watermark for r in inc)
            j.progress("download", message=top, force=True)
            changed = client.changed_since(top, since, INCREMENTAL_LIMIT)
            j.check()
            if changed is None:
                full += inc
            else:
                _incremental(j, db, client, top, set(inc), changed)
        if full:
            _full(j, db, client, full, spool_dir)


def _incremental(j, db: Session, client: osv.OsvClient, top: str, rels: Set[str], changed) -> None:
    loader = _Loader(db, j.check)
    ids = [rid for _, rid in changed]
    done = 0
    for k in range(0, len(ids), 200):
        chunk = ids[k:k + 200]
        fetched = list(client.records(top, chunk, cancelled=j.cancelled,
                                      on_progress=lambda n: j.progress("download", done + n, len(ids))))
        done += len(chunk)
        store.clear_records(db, chunk, rels)
        for _, rec in fetched:
            if rec is not None:
                loader.add(osv.rows_from(rec, rels))
        loader.flush()
    newest = max((when for when, _ in changed), default=None)
    for r in sorted(rels):
        store.refresh_counts(db, r, source="online", watermark=newest, full=False, changes=len(changed))
        j.stats["updated"].append(r)
    j.stats["records"] += len(changed)
    j.stats["rows"] += loader.written


def _full(j, db: Session, client: osv.OsvClient, rels: List[str], spool_dir: str) -> None:
    wanted = set(rels)
    paths = []
    for r in rels:
        for b in releases.bundles(r):
            if b not in paths:
                paths.append(b)
    files = []
    try:
        for b in paths:
            dest = os.path.join(spool_dir, f"job-{j.id}-{hashlib.sha1(b.encode()).hexdigest()[:10]}.zip")
            files.append(dest)
            j.progress("download", 0, None, message=b, force=True)
            if not client.download(b, dest, on_progress=lambda d, t, b=b: j.progress("download", d, t, message=b),
                                   cancelled=j.cancelled):
                files.pop()
        j.check()
        for r in rels:
            store.clear(db, r)
        loader = _Loader(db, j.check)
        for f in files:
            j.progress("apply", message=os.path.basename(f), force=True)
            _load_zip(loader, f, wanted, on_record=lambda n: j.progress("apply", n, None))
        for r in rels:
            store.refresh_counts(db, r, source="online", watermark=loader.watermark.get(r), full=True,
                                 changes=len(loader.records.get(r, ())))
            j.stats["loaded"].append(r)
            j.stats["records"] += len(loader.records.get(r, ()))
        j.stats["rows"] += loader.written
    finally:
        for f in files:
            if os.path.exists(f):
                os.remove(f)


# ── OSV archive import ───────────────────────────────────────────────────

def import_zip(j, db: Session, path: str) -> None:
    j.progress("verify", force=True)
    present: Dict[str, Set[str]] = defaultdict(set)       # release -> streams in the file
    mentions: Dict[str, int] = defaultdict(int)           # release -> records naming it
    n = 0
    for rec in osv.iter_zip(path):
        n += 1
        named = set()
        for a in rec.get("affected") or []:
            if isinstance(a, dict):
                eco = str((a.get("package") or {}).get("ecosystem") or "")
                found = releases.from_ecosystem(eco)
                if found:
                    present[found[0]].add(eco)
                    named.add(found[0])
        for r in named:
            mentions[r] += 1
        if n % 1000 == 0:
            j.check()
            j.progress("verify", n, None)
    # A per-release archive (Ubuntu:22.04:LTS, Debian:12) also names the other
    # releases its records touch, but holds only part of theirs: those must
    # not replace a complete load. Such a file is recognised by one release
    # named in (nearly) every record; a distribution-wide archive has none.
    dominant = {r for r in present if mentions[r] >= 0.95 * n}
    if dominant:
        present = defaultdict(set, {r: present[r] for r in dominant})
    if not present:
        raise osv.FeedError("The file holds no advisory of a supported distribution (Ubuntu, Debian, Red Hat, "
                            "Rocky Linux, AlmaLinux). Download all.zip of the release from OSV.dev.")
    kept = store.tracked(db)
    wanted = {r for r in present if r in kept} or set(present)
    with open(path, "rb") as fh:
        digest = hashlib.sha256()
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    j.stats.update({"releases": sorted(wanted), "loaded": sorted(wanted), "updated": [], "file_records": n,
                    "sha256": digest.hexdigest()})
    for r in wanted:
        store.clear(db, r, present[r])
    loader = _Loader(db, j.check)
    j.progress("apply", 0, n, force=True)
    _load_zip(loader, path, wanted, on_record=lambda k: j.progress("apply", k, n))
    for r in sorted(wanted):
        store.refresh_counts(db, r, source="osv_zip", watermark=loader.watermark.get(r), full=True,
                             changes=len(loader.records.get(r, ())))
    j.stats["records"] = sum(len(v) for v in loader.records.values())
    j.stats["rows"] = loader.written


# ── signed packages ──────────────────────────────────────────────────────

def apply_package(db: Session, info: Dict[str, dict], rows: Iterable[dict], check: Callable[[], None]) -> List[str]:
    """Advisories from a verified .ngcve: each release the package carries
    replaces this instance's when it is newer. Returns the releases taken."""
    feeds = {f.release: f for f in db.query(DistroFeed)}
    take = set()
    for release, meta in (info or {}).items():
        if not releases.valid(release):
            continue
        wm = osv._dt(meta.get("watermark"))
        current = feeds.get(release)
        if current is None or current.watermark is None or (wm and wm > current.watermark):
            take.add(release)
    if not take:
        return []
    for r in take:
        store.clear(db, r)
    loader = _Loader(db, check)
    for row in rows:
        if row.get("release") in take:
            row = dict(row)
            row["published"], row["modified"] = osv._dt(row.get("published")), osv._dt(row.get("modified"))
            loader.add([row])
    loader.flush()
    for r in sorted(take):
        store.refresh_counts(db, r, source="package", watermark=osv._dt(info[r].get("watermark")), full=True,
                             changes=len(loader.records.get(r, ())))
    return sorted(take)
