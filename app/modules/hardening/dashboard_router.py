"""
Hardening Dashboard Router

Read-only dashboard endpoints that combine hardening activity with the risk
engine's per-asset scores. Access is governed by the HARDENING module
permission, matching the codebase-wide require_permission(module, type) pattern.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User
from app.models.asset import Asset
from app.models.hardening import HardeningAction
from app.models.risk import AssetRiskScore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hardening/dashboard", tags=["Hardening Dashboard"])


# Columns the caller may sort by -> the SQLAlchemy expression backing each.
_SORTABLE_COLUMNS = {
    "final_risk_score": AssetRiskScore.final_risk_score,
    "risk_level": AssetRiskScore.risk_level,
    "active_findings_count": AssetRiskScore.active_audit_findings_count,
    "resolved_by_hardening": AssetRiskScore.resolved_by_hardening_count,
    "asset_name": Asset.asset_name,
}


def _dt(value):
    return value.isoformat() if value is not None else None


def _num(value):
    return float(value) if value is not None else None


@router.get("/assets-requiring-hardening")
def assets_requiring_hardening(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    risk_level: str = Query(None),
    sort_by: str = Query("final_risk_score"),
    sort_order: str = Query("desc"),
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """Paginated list of assets that still have active audit findings, ranked
    by their current risk score. Each row carries how many findings have
    already been resolved by hardening and when the asset was last hardened."""
    if sort_by not in _SORTABLE_COLUMNS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by; allowed: {', '.join(sorted(_SORTABLE_COLUMNS))}",
        )

    # Latest hardening execution per asset (NULL executed_at previews ignored).
    last_hardening = (
        db.query(
            HardeningAction.asset_id.label("asset_id"),
            func.max(HardeningAction.executed_at).label("last_date"),
        )
        .group_by(HardeningAction.asset_id)
        .subquery()
    )

    query = (
        db.query(AssetRiskScore, Asset, last_hardening.c.last_date)
        .join(Asset, Asset.id == AssetRiskScore.asset_id)
        .outerjoin(last_hardening, last_hardening.c.asset_id == AssetRiskScore.asset_id)
        .filter(AssetRiskScore.active_audit_findings_count > 0)
    )
    if risk_level:
        query = query.filter(AssetRiskScore.risk_level == risk_level)

    total = query.count()

    column = _SORTABLE_COLUMNS[sort_by]
    order = column.desc() if sort_order.lower() == "desc" else column.asc()
    rows = (
        query.order_by(order, AssetRiskScore.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    items = [
        {
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "ip_address": asset.ip_address,
            "vendor": asset.manufacturer,
            "risk_score": _num(score.final_risk_score),
            "risk_level": score.risk_level,
            "active_findings_count": score.active_audit_findings_count,
            "resolved_by_hardening": score.resolved_by_hardening_count,
            "last_hardening_date": _dt(last_date),
        }
        for score, asset, last_date in rows
    ]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
    }
