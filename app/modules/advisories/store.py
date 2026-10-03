"""
Advisory data in the database: which releases to keep, loading rows, the
state of each release's feed.

A release is kept when an asset runs it (from the latest successful Linux
software collection), when an admin asked for it, or when it was loaded
before (an import of another release is not thrown away).
"""
from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set

from sqlalchemy import delete, func, insert
from sqlalchemy.orm import Session

from app.models.advisory import DistroFeed, DistroVuln
from app.models.software import SoftwareCollection
from app.modules.advisories import releases
from app.modules.cve import settings as cve_settings

EXTRA_RELEASES = "advisory_releases"      # cve_settings: releases kept besides those in use
AUTO = "advisory_auto"                    # cve_settings: {"enabled": bool}
LAST_AUTO_RUN = "advisory_last_auto_run"  # date of the last daily automatic update
LAST_ATTEMPT = "advisory_last_attempt"    # ISO time of the last automatic attempt
BATCH = 5000


def platforms(db: Session, asset_ids: Optional[Iterable[int]] = None) -> Dict[int, dict]:
    """{asset id: platform} from each asset's latest successful Linux collection."""
    q = (db.query(SoftwareCollection.asset_id, SoftwareCollection.summary)
         .filter(SoftwareCollection.collector == "linux", SoftwareCollection.status == "ok"))
    if asset_ids is not None:
        ids = list(asset_ids)
        if not ids:
            return {}
        q = q.filter(SoftwareCollection.asset_id.in_(ids))
    out: Dict[int, dict] = {}
    for aid, summary in q.order_by(SoftwareCollection.asset_id, SoftwareCollection.collected_at.desc()):
        if aid not in out:
            out[aid] = (summary or {}).get("platform") or {}
    return out


def in_use(db: Session) -> Dict[str, List[int]]:
    out = defaultdict(list)
    for aid, platform in platforms(db).items():
        release, status = releases.from_platform(platform)
        if status == "ok":
            out[release].append(aid)
    return dict(out)


def extra(db: Session) -> List[str]:
    return [r for r in (cve_settings.get(db, EXTRA_RELEASES) or []) if releases.valid(r)]


def tracked(db: Session) -> Set[str]:
    have = {r for (r,) in db.query(DistroFeed.release)}
    return set(in_use(db)) | set(extra(db)) | have


def auto_enabled(db: Session) -> bool:
    return bool((cve_settings.get(db, AUTO) or {}).get("enabled", True))


def loaded(db: Session) -> bool:
    return db.query(DistroFeed.id).filter(DistroFeed.rows > 0).first() is not None


# ── writing (the caller commits) ─────────────────────────────────────────

def insert_rows(db: Session, rows: List[dict]) -> int:
    for k in range(0, len(rows), BATCH):
        db.execute(insert(DistroVuln), rows[k:k + BATCH])
    return len(rows)


def clear(db: Session, release: str, streams: Optional[Set[str]] = None) -> None:
    q = delete(DistroVuln).where(DistroVuln.release == release)
    if streams is not None:
        q = q.where(DistroVuln.stream.in_(list(streams)))
    db.execute(q)


def clear_records(db: Session, record_ids: List[str], release_set: Set[str]) -> None:
    for k in range(0, len(record_ids), 1000):
        db.execute(delete(DistroVuln).where(DistroVuln.record_id.in_(record_ids[k:k + 1000]),
                                            DistroVuln.release.in_(list(release_set))))


def feed(db: Session, release: str) -> DistroFeed:
    row = db.query(DistroFeed).filter(DistroFeed.release == release).first()
    if row is None:
        row = DistroFeed(release=release, rows=0, records=0)
        db.add(row)
        db.flush()
    return row


def refresh_counts(db: Session, release: str, *, source: str, watermark: Optional[datetime], full: bool,
                   changes: Optional[int] = None) -> DistroFeed:
    db.flush()
    row = feed(db, release)
    row.rows = db.query(func.count(DistroVuln.id)).filter(DistroVuln.release == release).scalar() or 0
    row.records = (db.query(func.count(func.distinct(DistroVuln.record_id)))
                   .filter(DistroVuln.release == release).scalar() or 0)
    if watermark and (row.watermark is None or full or watermark > row.watermark):
        row.watermark = watermark
    now = datetime.utcnow()
    if full:
        row.loaded_at = now
    row.updated_at, row.source, row.error = now, source, None
    row.last_changes = changes
    return row
