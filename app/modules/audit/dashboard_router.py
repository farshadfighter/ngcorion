"""
Auditing Dashboard API

Read-only aggregate endpoints backing the Auditing KPI dashboard. Everything is
derived from data the audit flow already writes (audit_sessions / audit_results)
— no new tables, no writes.

Mirrors the shape of app/modules/hardening/dashboard_router.py so the two
dashboards stay consistent.
"""
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User
from app.models.audit import CheckStatus, DeviceType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit/dashboard", tags=["Audit Dashboard"])


def _rows(db: Session, sql: str, params: Dict[str, Any] | None = None) -> List[Dict]:
    return [dict(r) for r in db.execute(text(sql), params or {}).mappings()]


def _pct(part: int, whole: int) -> float:
    """Percentage rounded to one decimal; 0 when there is nothing to divide."""
    return round(100.0 * part / whole, 1) if whole else 0.0


# device_type is a SQLEnum, so raw SQL reads back the member *name* ("CISCO").
# Map it to the lowercase API value the rest of the app uses.
_DEVICE_BY_NAME = {e.name: e.value for e in DeviceType}


def _device(value):
    return _DEVICE_BY_NAME.get(value, value)


@router.get("/overview")
def audit_overview(
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Headline counters across every audit session."""
    row = db.execute(text("""
        SELECT
            COUNT(*)                                        AS total_sessions,
            COUNT(*) FILTER (WHERE status = 'completed')    AS completed,
            COUNT(*) FILTER (WHERE status = 'failed')       AS failed,
            COUNT(*) FILTER (WHERE status = 'running')      AS running,
            COUNT(DISTINCT asset_id)                        AS audited_assets,
            COALESCE(SUM(total_checks), 0)                  AS total_checks,
            COALESCE(SUM(passed_checks), 0)                 AS passed_checks,
            COALESCE(SUM(failed_checks), 0)                 AS failed_checks,
            ROUND(AVG(compliance_pct)::numeric, 1)          AS avg_compliance
        FROM audit_sessions
    """)).mappings().first()

    # Assets that exist but have never been audited.
    never_audited = db.execute(text("""
        SELECT COUNT(*) FROM asset_inventory a
        WHERE NOT EXISTS (
            SELECT 1 FROM audit_sessions s WHERE s.asset_id = a.id
        )
    """)).scalar() or 0

    total_checks = int(row["total_checks"] or 0)
    passed = int(row["passed_checks"] or 0)

    return {
        "total_sessions": int(row["total_sessions"] or 0),
        "completed_sessions": int(row["completed"] or 0),
        "failed_sessions": int(row["failed"] or 0),
        "running_sessions": int(row["running"] or 0),
        "audited_assets": int(row["audited_assets"] or 0),
        "never_audited_assets": int(never_audited),
        "total_checks": total_checks,
        "passed_checks": passed,
        "failed_checks": int(row["failed_checks"] or 0),
        # Average of each session's own percentage; falls back to the aggregate
        # pass ratio when no session stored one.
        "average_compliance": (
            float(row["avg_compliance"])
            if row["avg_compliance"] is not None
            else _pct(passed, total_checks)
        ),
    }


@router.get("/findings-by-severity")
def findings_by_severity(
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Failed checks grouped by severity — the first donut in the design."""
    rows = _rows(db, """
        SELECT
            COALESCE(NULLIF(severity, ''), 'unspecified') AS severity,
            COUNT(*)                                      AS count
        FROM audit_results
        WHERE status = :fail_status
        GROUP BY COALESCE(NULLIF(severity, ''), 'unspecified')
        ORDER BY COUNT(*) DESC
    """, {"fail_status": CheckStatus.FAIL.name})
    return {
        "items": [
            {"severity": r["severity"], "count": int(r["count"])}
            for r in rows
        ]
    }


@router.get("/top-failed-controls")
def top_failed_controls(
    limit: int = Query(10, ge=1, le=50),
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Controls failing on the most assets — the second donut in the design."""
    rows = _rows(db, """
        SELECT
            r.check_number,
            MAX(r.check_title)         AS check_title,
            MAX(r.severity)            AS severity,
            COUNT(*)                   AS fail_count,
            COUNT(DISTINCT s.asset_id) AS affected_assets
        FROM audit_results r
        JOIN audit_sessions s ON s.id = r.session_id
        WHERE r.status = :fail_status
        GROUP BY r.check_number
        ORDER BY COUNT(*) DESC, r.check_number ASC
        LIMIT :limit
    """, {"limit": limit, "fail_status": CheckStatus.FAIL.name})
    return {
        "items": [
            {
                "check_number": r["check_number"],
                "check_title": r["check_title"],
                "severity": r["severity"],
                "fail_count": int(r["fail_count"]),
                "affected_assets": int(r["affected_assets"]),
            }
            for r in rows
        ]
    }


@router.get("/compliance-trend")
def compliance_trend(
    months: int = Query(12, ge=1, le=36),
    days: int = Query(None, ge=1, le=180),
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """
    Average compliance over time.

    Grouped by day when `days` is given (the dashboard's 30-day view), by month
    otherwise. Period labels are YYYY-MM-DD and YYYY-MM respectively.
    """
    if days:
        rows = _rows(db, """
            SELECT
                TO_CHAR(DATE_TRUNC('day', started_at), 'YYYY-MM-DD') AS period,
                ROUND(AVG(compliance_pct)::numeric, 1)               AS average_compliance,
                COUNT(*)                                             AS session_count
            FROM audit_sessions
            WHERE started_at >= NOW() - make_interval(days => :days)
              AND compliance_pct IS NOT NULL
            GROUP BY DATE_TRUNC('day', started_at)
            ORDER BY DATE_TRUNC('day', started_at) ASC
        """, {"days": days})
    else:
        rows = _rows(db, """
            SELECT
                TO_CHAR(DATE_TRUNC('month', started_at), 'YYYY-MM') AS period,
                ROUND(AVG(compliance_pct)::numeric, 1)              AS average_compliance,
                COUNT(*)                                            AS session_count
            FROM audit_sessions
            WHERE started_at >= NOW() - make_interval(months => :months)
              AND compliance_pct IS NOT NULL
            GROUP BY DATE_TRUNC('month', started_at)
            ORDER BY DATE_TRUNC('month', started_at) ASC
        """, {"months": months})

    points = [
        {
            "period": r["period"],
            "average_compliance": float(r["average_compliance"] or 0),
            "session_count": int(r["session_count"]),
        }
        for r in rows
    ]
    if not points:
        return {"points": [], "message": "No completed audits yet."}
    return {"points": points}


@router.get("/compliance-by-device-type")
def compliance_by_device_type(
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Average compliance grouped by the audited device family."""
    rows = _rows(db, """
        SELECT
            device_type                            AS name,
            COUNT(*)                               AS session_count,
            ROUND(AVG(compliance_pct)::numeric, 1) AS average_compliance
        FROM audit_sessions
        WHERE compliance_pct IS NOT NULL
        GROUP BY device_type
        ORDER BY COUNT(*) DESC
    """)
    return {
        "items": [
            {
                "name": _device(r["name"]),
                "session_count": int(r["session_count"]),
                "percent": float(r["average_compliance"] or 0),
            }
            for r in rows
        ]
    }


@router.get("/remediation-progress")
def remediation_progress(
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """
    Open vs. remediated findings.

    "Fixed" means a failed check that a successful hardening action resolved,
    which is why this reads hardening_actions alongside audit_results.
    """
    row = db.execute(text("""
        SELECT
            COUNT(*) AS total_failed,
            COUNT(*) FILTER (
                WHERE EXISTS (
                    SELECT 1 FROM hardening_actions h
                    WHERE h.audit_result_id = r.id AND h.status = 'success'
                )
            ) AS fixed_total,
            COUNT(*) FILTER (
                WHERE EXISTS (
                    SELECT 1 FROM hardening_actions h
                    WHERE h.audit_result_id = r.id
                      AND h.status = 'success'
                      AND h.completed_at >= DATE_TRUNC('month', NOW())
                )
            ) AS fixed_this_month
        FROM audit_results r
        WHERE r.status = :fail_status
    """), {"fail_status": CheckStatus.FAIL.name}).mappings().first()

    total_failed = int(row["total_failed"] or 0)
    fixed_total = int(row["fixed_total"] or 0)

    return {
        "open_findings": total_failed - fixed_total,
        "fixed_this_month": int(row["fixed_this_month"] or 0),
        "fixed_total": fixed_total,
        "resolved_percent": _pct(fixed_total, total_failed),
    }


@router.get("/critical-findings")
def critical_findings(
    limit: int = Query(10, ge=1, le=100),
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Unresolved high/critical findings, worst first."""
    rows = _rows(db, """
        SELECT
            r.id,
            r.check_number,
            r.check_title,
            r.severity,
            r.checked_at,
            a.asset_name,
            s.id AS session_id
        FROM audit_results r
        JOIN audit_sessions s   ON s.id = r.session_id
        LEFT JOIN asset_inventory a ON a.id = s.asset_id
        WHERE r.status = :fail_status
          AND LOWER(COALESCE(r.severity, '')) IN ('critical', 'high')
          AND NOT EXISTS (
              SELECT 1 FROM hardening_actions h
              WHERE h.audit_result_id = r.id AND h.status = 'success'
          )
        ORDER BY
            CASE LOWER(r.severity) WHEN 'critical' THEN 0 ELSE 1 END,
            r.checked_at DESC NULLS LAST
        LIMIT :limit
    """, {"limit": limit, "fail_status": CheckStatus.FAIL.name})
    return {
        "items": [
            {
                "id": int(r["id"]),
                "session_id": int(r["session_id"]),
                "asset_name": r["asset_name"],
                "check_number": r["check_number"],
                "check_title": r["check_title"],
                "severity": r["severity"],
                "checked_at": r["checked_at"].isoformat() if r["checked_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/recent-sessions")
def recent_sessions(
    limit: int = Query(10, ge=1, le=100),
    _current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Latest audit sessions, newest first."""
    rows = _rows(db, """
        SELECT
            s.id, s.job_name, s.status, s.device_type, s.target_ip,
            s.total_checks, s.passed_checks, s.failed_checks,
            s.compliance_pct, s.started_at, s.completed_at,
            a.asset_name
        FROM audit_sessions s
        LEFT JOIN asset_inventory a ON a.id = s.asset_id
        ORDER BY s.started_at DESC
        LIMIT :limit
    """, {"limit": limit})
    return {
        "items": [
            {
                "session_id": int(r["id"]),
                "job_name": r["job_name"],
                "asset_name": r["asset_name"],
                "target_ip": r["target_ip"],
                "device_type": _device(r["device_type"]),
                "status": r["status"],
                "total_checks": int(r["total_checks"] or 0),
                "passed_checks": int(r["passed_checks"] or 0),
                "failed_checks": int(r["failed_checks"] or 0),
                "compliance_pct": (
                    float(r["compliance_pct"])
                    if r["compliance_pct"] is not None else None
                ),
                "started_at": r["started_at"].isoformat() if r["started_at"] else None,
                "completed_at": (
                    r["completed_at"].isoformat() if r["completed_at"] else None
                ),
            }
            for r in rows
        ]
    }
