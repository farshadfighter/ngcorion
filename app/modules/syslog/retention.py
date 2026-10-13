"""
Keeping the syslog tables bounded: messages older than the retention period go, and when the
messages table still takes more disk than its budget, the oldest go first until it fits (a burst
from a noisy device can never fill the disk). Addresses outside the inventory that have not sent
anything for 30 days are forgotten.

Deletes run in batches so no single statement holds a long lock.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.modules.syslog import settings as syslog_settings

logger = logging.getLogger(__name__)

BATCH = 20000
MAX_BATCHES = 200            # per run; the next run carries on
UNKNOWN_SOURCE_DAYS = 30


def table_bytes(db: Session) -> int:
    return int(db.execute(text("SELECT pg_total_relation_size('syslog_messages')")).scalar() or 0)


def _delete_batch(db: Session, where: str, params: Dict) -> int:
    n = db.execute(text(
        f"DELETE FROM syslog_messages WHERE id IN (SELECT id FROM syslog_messages WHERE {where} "  # nosec B608 - fixed clauses below
        "ORDER BY id LIMIT :batch)"), {**params, "batch": BATCH}).rowcount
    db.commit()
    return n or 0


def prune(db: Session, now: Optional[datetime] = None) -> Dict[str, int]:
    """Returns how many messages went by age and by size, and how many unknown addresses."""
    now = now or datetime.utcnow()
    cfg = syslog_settings.get_settings(db)
    before = now - timedelta(days=cfg["retention_days"])
    by_age = by_size = 0
    for _ in range(MAX_BATCHES):
        n = _delete_batch(db, "received_at < :before", {"before": before})
        by_age += n
        if n < BATCH:
            break
    budget = cfg["storage_budget_gb"] * 1024 ** 3
    # pg_total_relation_size does not shrink on DELETE until autovacuum reuses the space; deleting
    # down to 80% of the budget leaves room so this does not run on every check.
    if table_bytes(db) > budget:
        total = db.execute(text("SELECT count(*) FROM syslog_messages")).scalar() or 0
        target = int(total * 0.8 * budget / max(table_bytes(db), 1))
        excess = max(total - target, 0)
        while excess > 0 and by_size < BATCH * MAX_BATCHES:
            n = _delete_batch(db, "TRUE", {})
            if not n:
                break
            by_size += n
            excess -= n
        logger.warning("[Syslog] messages table over its %s GB budget: removed the %d oldest messages",
                       cfg["storage_budget_gb"], by_size)
    forgotten = db.execute(text(
        "DELETE FROM syslog_sources WHERE asset_id IS NULL AND last_seen < :t"),
        {"t": now - timedelta(days=UNKNOWN_SOURCE_DAYS)}).rowcount or 0
    db.commit()
    return {"by_age": by_age, "by_size": by_size, "unknown_sources": forgotten}
