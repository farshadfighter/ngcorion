"""
Hardening Dashboard API

Read-only aggregate endpoints backing the Hardening KPI dashboard. Everything
here is derived from data the hardening flow already writes (hardening_actions,
joined to audit_results / asset_inventory) — no new tables, no writes.

One panel from the design is still absent because it needs a product decision
rather than a query: "Hardening Impact" (before/after findings) has nothing
recording the pre-hardening baseline, the same gap the risk module has.
"""
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User
from app.models.audit import CheckStatus
from app.models.asset import Asset
from app.models.hardening import HardeningAction
from app.models.risk import AssetRiskScore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hardening/dashboard", tags=["Hardening Dashboard"])

# hardening_actions.status values written by the hardening flow.
SUCCESS_STATUSES = ("success",)
FAILED_STATUSES = ("failed",)
PENDING_STATUSES = ("pending", "executing")


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


def _rows(db: Session, sql: str, params: Dict[str, Any] | None = None) -> List[Dict]:
    return [dict(r) for r in db.execute(text(sql), params or {}).mappings()]


def _pct(part: int, whole: int) -> float:
    """Percentage rounded to one decimal; 0 when there is nothing to divide."""
    return round(100.0 * part / whole, 1) if whole else 0.0


@router.get("/overview")
def hardening_overview(
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """The six headline counters plus the automation success split."""
    row = db.execute(text("""
        SELECT
            COUNT(*)                                                   AS total_actions,
            COUNT(*) FILTER (WHERE status = 'success')                 AS successful,
            COUNT(*) FILTER (WHERE status = 'failed')                  AS failed,
            COUNT(*) FILTER (WHERE status IN ('pending', 'executing')) AS pending,
            COUNT(DISTINCT asset_id)                                   AS assets_touched,
            COUNT(DISTINCT check_number)                               AS distinct_controls
        FROM hardening_actions
    """)).mappings().first()

    total = int(row["total_actions"] or 0)
    successful = int(row["successful"] or 0)
    failed = int(row["failed"] or 0)
    hardened_assets = int(row["assets_touched"] or 0)

    # Assets that exist but have never had a hardening action applied.
    non_hardened = db.execute(text("""
        SELECT COUNT(*) AS c
        FROM asset_inventory a
        WHERE NOT EXISTS (
            SELECT 1 FROM hardening_actions h WHERE h.asset_id = a.id
        )
    """)).scalar() or 0

    return {
        # "Hardening Score" in the design: share of applied actions that succeeded.
        "hardening_score": _pct(successful, successful + failed),
        "hardened_assets": hardened_assets,
        "non_hardened_assets": int(non_hardened),
        "applied_policies": total,
        "failed_actions": failed,
        "pending_actions": int(row["pending"] or 0),
        "distinct_controls": int(row["distinct_controls"] or 0),
        "automation": {
            "executed_tasks": total,
            "success_rate": _pct(successful, total),
            "success": successful,
            "failed": failed,
        },
    }


@router.get("/progress")
def hardening_progress(
    months: int = Query(12, ge=1, le=36),
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """Monthly success rate over the last N months."""
    rows = _rows(db, """
        SELECT
            TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM') AS period,
            COUNT(*)                                   AS total,
            COUNT(*) FILTER (WHERE status = 'success') AS successful
        FROM hardening_actions
        WHERE created_at >= NOW() - make_interval(months => :months)
        GROUP BY DATE_TRUNC('month', created_at)
        ORDER BY DATE_TRUNC('month', created_at) ASC
    """, {"months": months})

    points = [
        {
            "period": r["period"],
            "success_rate": _pct(int(r["successful"] or 0), int(r["total"] or 0)),
            "total": int(r["total"] or 0),
            "successful": int(r["successful"] or 0),
        }
        for r in rows
    ]
    if not points:
        return {"points": [], "message": "No hardening activity recorded yet."}
    return {"points": points}


@router.get("/coverage-by-asset-type")
def coverage_by_asset_type(
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """Per asset type: share of assets that have at least one successful action."""
    rows = _rows(db, """
        SELECT
            COALESCE(t.type_name, 'Unknown') AS name,
            COUNT(DISTINCT a.id)             AS total_assets,
            COUNT(DISTINCT a.id) FILTER (
                WHERE EXISTS (
                    SELECT 1 FROM hardening_actions h
                    WHERE h.asset_id = a.id AND h.status = 'success'
                )
            ) AS hardened_assets
        FROM asset_inventory a
        LEFT JOIN asset_types t ON t.id = a.asset_type_id
        GROUP BY t.type_name
        HAVING COUNT(DISTINCT a.id) > 0
        ORDER BY COUNT(DISTINCT a.id) DESC
    """)
    return {
        "items": [
            {
                "name": r["name"],
                "total_assets": int(r["total_assets"]),
                "hardened_assets": int(r["hardened_assets"]),
                "percent": _pct(int(r["hardened_assets"]), int(r["total_assets"])),
            }
            for r in rows
        ]
    }


@router.get("/by-vendor")
def hardening_by_vendor(
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """Success rate of hardening actions grouped by the asset's manufacturer."""
    rows = _rows(db, """
        SELECT
            COALESCE(NULLIF(a.manufacturer, ''), 'Unknown') AS name,
            COUNT(*)                                        AS total,
            COUNT(*) FILTER (WHERE h.status = 'success')    AS successful
        FROM hardening_actions h
        JOIN asset_inventory a ON a.id = h.asset_id
        GROUP BY COALESCE(NULLIF(a.manufacturer, ''), 'Unknown')
        ORDER BY COUNT(*) DESC
    """)
    return {
        "items": [
            {
                "name": r["name"],
                "total": int(r["total"]),
                "successful": int(r["successful"]),
                "percent": _pct(int(r["successful"]), int(r["total"])),
            }
            for r in rows
        ]
    }


@router.get("/policy-compliance")
def policy_compliance(
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Success rate per CIS level.

    hardening_actions has no level column of its own; the level lives on the
    audit_results row each action was created from, hence the join.
    """
    rows = _rows(db, """
        SELECT
            COALESCE(NULLIF(r.level, ''), 'Unspecified') AS level,
            COUNT(*)                                     AS total,
            COUNT(*) FILTER (WHERE h.status = 'success') AS successful
        FROM hardening_actions h
        JOIN audit_results r ON r.id = h.audit_result_id
        GROUP BY COALESCE(NULLIF(r.level, ''), 'Unspecified')
        ORDER BY COALESCE(NULLIF(r.level, ''), 'Unspecified') ASC
    """)
    return {
        "items": [
            {
                "level": r["level"],
                "total": int(r["total"]),
                "successful": int(r["successful"]),
                "percent": _pct(int(r["successful"]), int(r["total"])),
            }
            for r in rows
        ]
    }


@router.get("/recent-activities")
def recent_activities(
    limit: int = Query(10, ge=1, le=100),
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """Latest hardening actions, newest first."""
    rows = _rows(db, """
        SELECT
            h.id, h.check_number, h.check_title, h.status, h.action_type,
            h.created_at, h.completed_at,
            a.asset_name
        FROM hardening_actions h
        LEFT JOIN asset_inventory a ON a.id = h.asset_id
        ORDER BY h.created_at DESC
        LIMIT :limit
    """, {"limit": limit})
    return {
        "items": [
            {
                "id": int(r["id"]),
                "check_number": r["check_number"],
                "check_title": r["check_title"],
                "asset_name": r["asset_name"],
                "status": r["status"],
                "action_type": r["action_type"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "completed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/top-missing-controls")
def top_missing_controls(
    limit: int = Query(10, ge=1, le=50),
    _current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Controls still failing across the estate: audit checks with status FAIL that
    have no successful hardening action, ranked by how many assets they affect.
    """
    # audit_results.status is a SQLEnum, so the column stores the member *name*
    # ("FAIL"). Take it from the enum rather than hardcoding the string.
    rows = _rows(db, """
        SELECT
            r.check_number,
            MAX(r.check_title)              AS check_title,
            MAX(r.severity)                 AS severity,
            COUNT(DISTINCT s.asset_id)      AS affected_assets
        FROM audit_results r
        JOIN audit_sessions s ON s.id = r.session_id
        WHERE r.status = :fail_status
          AND NOT EXISTS (
              SELECT 1 FROM hardening_actions h
              WHERE h.audit_result_id = r.id AND h.status = 'success'
          )
        GROUP BY r.check_number
        ORDER BY COUNT(DISTINCT s.asset_id) DESC, r.check_number ASC
        LIMIT :limit
    """, {"limit": limit, "fail_status": CheckStatus.FAIL.name})
    return {
        "items": [
            {
                "check_number": r["check_number"],
                "check_title": r["check_title"],
                "severity": r["severity"],
                "affected_assets": int(r["affected_assets"]),
            }
            for r in rows
        ]
    }


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
