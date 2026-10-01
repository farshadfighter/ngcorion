"""
Writing normalised feed records into the database.

Everything here runs inside the caller's transaction and never commits: an
update writes all of its changes - CVEs, KEV flags, EPSS scores, the new
watermark - and commits once, so a failed or cancelled update leaves the
previous database untouched.
"""
from datetime import date, datetime
from typing import Iterable, List, Optional

from sqlalchemy import delete, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.cve import CveCpeMatch, CveEntry
from app.modules.cve.feeds import safe_url

BATCH = 1000


def _dt(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value) if value else None


def _d(value: Optional[str]) -> Optional[date]:
    return date.fromisoformat(value) if value else None


def apply_cve_batch(db: Session, records: List[dict]) -> dict:
    """Upsert one batch. Returns {"new", "changed", "removed"}."""
    stats = {"new": 0, "changed": 0, "removed": 0}
    if not records:
        return stats
    ids = [r["id"] for r in records]
    existing = dict(db.execute(select(CveEntry.cve_id, CveEntry.last_modified).where(CveEntry.cve_id.in_(ids))).all())

    rejected = [r["id"] for r in records if r.get("rejected")]
    if rejected:
        stats["removed"] = len(set(existing) & set(rejected))
        db.execute(delete(CveEntry).where(CveEntry.cve_id.in_(rejected)))

    # An older copy never overwrites a newer one (e.g. importing an old package
    # after an online update).
    live = [r for r in records if not r.get("rejected") and not (
        existing.get(r["id"]) and r.get("modified") and _dt(r["modified"]) < existing[r["id"]])]
    if not live:
        return stats
    rows = [{
        "cve_id": r["id"], "published": _dt(r.get("published")), "last_modified": _dt(r.get("modified")),
        "status": r.get("status"), "description": r.get("description") or "",
        "cvss_score": r["cvss"].get("score"), "cvss_version": r["cvss"].get("version"),
        "severity": r["cvss"].get("severity"), "cvss_vector": r["cvss"].get("vector"),
        "cwe": r.get("cwe"), "references": [u for u in (r.get("refs") or []) if safe_url(u)][:8],
        "updated_at": datetime.utcnow(),
    } for r in live]
    stmt = insert(CveEntry).values(rows)
    # KEV and EPSS columns are owned by their own feeds - an NVD update keeps them.
    stmt = stmt.on_conflict_do_update(
        index_elements=[CveEntry.cve_id],
        set_={c: stmt.excluded[c] for c in ("published", "last_modified", "status", "description", "cvss_score",
                                             "cvss_version", "severity", "cvss_vector", "cwe", "references",
                                             "updated_at")},
    )
    db.execute(stmt)

    live_ids = [r["id"] for r in live]
    db.execute(delete(CveCpeMatch).where(CveCpeMatch.cve_id.in_(live_ids)))
    matches = [{"cve_id": r["id"], **c} for r in live for c in r.get("cpes", [])]
    for i in range(0, len(matches), 5000):
        db.execute(insert(CveCpeMatch), matches[i:i + 5000])

    stats["new"] = sum(1 for i in live_ids if i not in existing)
    stats["changed"] = len(live_ids) - stats["new"]
    return stats


def apply_cves(db: Session, records: Iterable[dict], on_batch=None) -> dict:
    total = {"new": 0, "changed": 0, "removed": 0}
    batch: List[dict] = []
    for r in records:
        batch.append(r)
        if len(batch) >= BATCH:
            for k, v in apply_cve_batch(db, batch).items():
                total[k] += v
            batch = []
            if on_batch:
                on_batch(total)
    for k, v in apply_cve_batch(db, batch).items():
        total[k] += v
    return total


def apply_kev(db: Session, kev: dict) -> int:
    """Replace the KEV flags with this catalogue. Returns how many CVEs in the
    database it marks."""
    db.execute(update(CveEntry).where(CveEntry.kev.is_(True))
               .values(kev=False, kev_added=None, kev_due=None, kev_ransomware=None, kev_action=None))
    marked = 0
    items = kev.get("items", [])
    for i in range(0, len(items), BATCH):
        chunk = items[i:i + BATCH]
        for item in chunk:
            res = db.execute(update(CveEntry).where(CveEntry.cve_id == item["id"]).values(
                kev=True, kev_added=_d(item.get("added")), kev_due=_d(item.get("due")),
                kev_ransomware=item.get("ransomware"), kev_action=item.get("action")))
            marked += res.rowcount or 0
    return marked


def apply_epss(db: Session, rows: List[tuple]) -> int:
    """rows: (cve_id, epss, percentile). Set-based, in chunks."""
    updated = 0
    for i in range(0, len(rows), 5000):
        chunk = rows[i:i + 5000]
        params, values = {}, []
        for n, (cve_id, score, pct) in enumerate(chunk):
            params[f"i{n}"], params[f"e{n}"], params[f"p{n}"] = cve_id, score, pct
            values.append(f"(:i{n}, CAST(:e{n} AS double precision), CAST(:p{n} AS double precision))")
        res = db.execute(text(
            "UPDATE cve_entries AS c SET epss = v.e, epss_percentile = v.p "
            f"FROM (VALUES {', '.join(values)}) AS v(id, e, p) WHERE c.cve_id = v.id"
        ), params)
        updated += res.rowcount or 0
    return updated
