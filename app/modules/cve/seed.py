"""
CVE Module Seed Data

Seeds the curated CVE records from seed_data.py. Idempotent: matched by the
same composite key as the DB's uq_cve_records_branch constraint
(cve_id, product_keyword, affected_version_min, affected_version_max), so
re-running never duplicates rows and never touches rows added later by an
NVD sync.

Run directly:  python -m app.modules.cve.seed
Or call seed_cve_defaults(db) from application startup.
"""

import logging

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.cve import CveRecord
from app.modules.cve.seed_data import SEED_RECORDS

logger = logging.getLogger(__name__)


def seed_cve_defaults(db: Session) -> dict:
    """Insert missing seed CVE records. Returns count of rows added."""
    added = 0
    for record in SEED_RECORDS:
        exists = (
            db.query(CveRecord)
            .filter(
                CveRecord.cve_id == record["cve_id"],
                CveRecord.product_keyword == record["product_keyword"],
                CveRecord.affected_version_min == record.get("affected_version_min"),
                CveRecord.affected_version_max == record.get("affected_version_max"),
            )
            .first()
        )
        if exists:
            continue
        db.add(CveRecord(**record, source="seed"))
        added += 1

    db.commit()
    logger.info("CVE seed: %d records added", added)
    return {"records_added": added}


def main():
    logging.basicConfig(level=logging.INFO)
    db = SessionLocal()
    try:
        result = seed_cve_defaults(db)
        print(f"Seed complete: {result['records_added']} records added")
    finally:
        db.close()


if __name__ == "__main__":
    main()
