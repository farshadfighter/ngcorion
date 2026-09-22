"""
CVE Service

Assembles per-asset and all-asset vulnerability findings by joining the real
asset inventory against the local CveRecord table via matcher.asset_matches_cve
at read time - there is deliberately no persisted match table (see
app/models/cve.py).
"""
import logging
from typing import Optional

import requests
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.cve import CveRecord
from app.modules.cve.matcher import asset_matches_cve
from app.modules.cve import nvd_sync

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class CveService:
    """CVE Vulnerability Service."""

    @staticmethod
    def get_findings(db: Session, asset_id: Optional[int] = None) -> dict:
        assets_query = db.query(Asset).filter(Asset.os_name.isnot(None), Asset.os_version.isnot(None))
        if asset_id is not None:
            assets_query = assets_query.filter(Asset.id == asset_id)
        assets = assets_query.all()

        cve_records = db.query(CveRecord).all()

        findings = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for asset in assets:
            for cve in cve_records:
                if not asset_matches_cve(asset, cve):
                    continue
                findings.append({
                    "asset_id": asset.id,
                    "asset_name": asset.asset_name,
                    "manufacturer": asset.manufacturer,
                    "os_name": asset.os_name,
                    "os_version": asset.os_version,
                    "cve": cve,
                })
                severity = (cve.severity or "").lower()
                if severity in counts:
                    counts[severity] += 1

        findings.sort(
            key=lambda f: (_SEVERITY_ORDER.get((f["cve"].severity or "").lower(), 99), f["asset_id"])
        )

        return {
            "summary": {
                "total": len(findings),
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
            },
            "findings": findings,
        }

    @staticmethod
    def list_records(db: Session):
        return db.query(CveRecord).order_by(CveRecord.cve_id).all()

    @staticmethod
    def sync_from_nvd(db: Session, product_keyword: Optional[str] = None) -> dict:
        """Manually-triggered sync. When product_keyword is given, syncs just
        that product (matched against TRACKED_PRODUCTS for its vendor/product
        display names, falling back to the keyword itself); otherwise syncs
        every tracked product. Raises requests.RequestException on a single-
        product sync failure - the caller (router) turns that into a 502."""
        if product_keyword is None:
            result = nvd_sync.sync_all_tracked_products(db)
            message = (
                f"{len(result['failures'])} product(s) could not be reached: {', '.join(result['failures'])}"
                if result["failures"] else None
            )
            return {**result, "source": "nvd", "message": message}

        match = next(
            (p for p in nvd_sync.TRACKED_PRODUCTS if p[2] == product_keyword),
            (product_keyword.title(), product_keyword.title(), product_keyword),
        )
        vendor, product, keyword = match
        result = nvd_sync.sync_product_from_nvd(db, keyword, vendor, product)
        return {**result, "source": "nvd", "message": None}
