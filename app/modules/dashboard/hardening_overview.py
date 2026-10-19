"""
The hardening overview: how hardening is going, what needs a person, which controls are still missing,
what hardening changed in risk terms, and how far it reaches. Read with the hardening permission; only
executed actions count (previews are not hardening).

  figures       success rate (succeeded of succeeded + failed), actions done, assets hardened, assets
                never hardened, open failures, pending actions, actions in the last 30 days.
  attention     failed actions not fixed by a later success (with the error and whether a backup lets
                you restore), changes not verified or not holding, and assets hardened since their
                last audit (the score still shows the old findings until they are audited again).
  missing       controls failing in each asset's latest audit with no successful fix, by assets affected.
  impact        critical and high findings hardening fixed, and the risk of the assets hardened in the
                last 90 days before their first change and now.
  coverage      assets with a successful change per asset type, success rate per benchmark level, and
                the latest actions.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models import User
from app.models.audit import CheckStatus

EXECUTED = "h.action_type <> 'preview'"
LISTED = 10
IMPACT_DAYS = 90


def _rows(db: Session, sql: str, params: Optional[Dict] = None) -> List[Dict]:
    return [dict(r) for r in db.execute(text(sql), params or {}).mappings()]


def _pct(part: int, whole: int) -> Optional[float]:
    return round(100.0 * part / whole, 1) if whole else None


def _iso(dt) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _tail(output: Optional[str], limit: int = 300) -> Optional[str]:
    """The end of a device output, where the error usually is."""
    if not output:
        return None
    output = output.strip()
    return output if len(output) <= limit else "…" + output[-limit:]


# A failed action that a later successful one on the same asset and control did not make good.
_OPEN_FAILED = f"""
    FROM hardening_actions h
    JOIN asset_inventory a ON a.id = h.asset_id
    WHERE {EXECUTED} AND h.status = 'failed'
      AND NOT EXISTS (
          SELECT 1 FROM hardening_actions s
          WHERE s.asset_id = h.asset_id AND s.check_number = h.check_number AND s.status = 'success'
            AND s.action_type <> 'preview' AND s.created_at > h.created_at
      )
"""

# Assets whose latest successful change came after their latest audit started.
_NOT_REAUDITED = f"""
    FROM (
        SELECT h.asset_id, MAX(COALESCE(h.executed_at, h.created_at)) AS hardened_at
        FROM hardening_actions h
        WHERE {EXECUTED} AND h.status = 'success'
        GROUP BY h.asset_id
    ) x
    JOIN asset_inventory a ON a.id = x.asset_id
    LEFT JOIN (
        SELECT asset_id, MAX(started_at) AS audited_at FROM audit_sessions
        WHERE asset_id IS NOT NULL AND status <> 'running' GROUP BY asset_id
    ) s ON s.asset_id = x.asset_id
    WHERE s.audited_at IS NULL OR s.audited_at < x.hardened_at
"""


def figures(db: Session, now: datetime) -> Dict:
    r = db.execute(text(f"""
        SELECT
            COUNT(*) FILTER (WHERE h.status IN ('success', 'failed'))       AS done,
            COUNT(*) FILTER (WHERE h.status = 'success')                    AS succeeded,
            COUNT(*) FILTER (WHERE h.status = 'failed')                     AS failed,
            COUNT(*) FILTER (WHERE h.status IN ('pending', 'executing'))    AS pending,
            COUNT(*) FILTER (WHERE h.created_at >= :since)                  AS last_30d,
            COUNT(DISTINCT h.asset_id) FILTER (WHERE h.status = 'success')  AS hardened
        FROM hardening_actions h WHERE {EXECUTED}
    """), {"since": now - timedelta(days=30)}).mappings().one()
    total_assets = db.execute(text("SELECT COUNT(*) FROM asset_inventory")).scalar() or 0
    open_failed = db.execute(text("SELECT COUNT(*) " + _OPEN_FAILED)).scalar() or 0
    succeeded, failed = int(r["succeeded"]), int(r["failed"])
    return {
        "success_rate": _pct(succeeded, succeeded + failed),
        "actions_done": int(r["done"]),
        "succeeded": succeeded,
        "failed": failed,
        "open_failures": int(open_failed),
        "pending": int(r["pending"]),
        "last_30d": int(r["last_30d"]),
        "hardened_assets": int(r["hardened"]),
        "never_hardened": int(total_assets) - int(r["hardened"]),
    }


def attention(db: Session) -> Dict:
    failed = _rows(db, f"""
        SELECT h.id, h.asset_id, a.asset_name, h.check_number, h.check_title, h.error_message, h.output,
               COALESCE(h.executed_at, h.created_at) AS at,
               (h.backup_config IS NOT NULL OR EXISTS (
                   SELECT 1 FROM device_backups b WHERE b.hardening_action_id = h.id)) AS has_backup
        {_OPEN_FAILED}
        ORDER BY COALESCE(h.executed_at, h.created_at) DESC, h.id DESC
        LIMIT :limit
    """, {"limit": LISTED})
    unverified = _rows(db, f"""
        SELECT h.id, h.asset_id, a.asset_name, h.check_number, h.check_title, h.verification_passed,
               COALESCE(h.executed_at, h.created_at) AS at
        FROM hardening_actions h JOIN asset_inventory a ON a.id = h.asset_id
        WHERE {EXECUTED} AND h.status = 'success' AND h.verification_passed IS NOT TRUE
        ORDER BY (h.verification_passed IS FALSE) DESC, COALESCE(h.executed_at, h.created_at) DESC, h.id DESC
    """)
    stale = _rows(db, f"""
        SELECT x.asset_id, a.asset_name, a.ip_address, x.hardened_at, s.audited_at
        {_NOT_REAUDITED}
        ORDER BY x.hardened_at DESC
    """)
    return {
        "failed": {
            "total": int(db.execute(text("SELECT COUNT(*) " + _OPEN_FAILED)).scalar() or 0),
            "items": [{"id": f["id"], "asset_id": f["asset_id"], "asset_name": f["asset_name"],
                       "check_number": f["check_number"], "check_title": f["check_title"],
                       "error": f["error_message"] or _tail(f["output"]), "at": _iso(f["at"]),
                       "has_backup": bool(f["has_backup"]),
                       "restore_link": f"/backup?asset={f['asset_id']}"} for f in failed],
        },
        "unverified": {
            "total": len(unverified),
            "not_holding": sum(1 for u in unverified if u["verification_passed"] is False),
            "items": [{"id": u["id"], "asset_id": u["asset_id"], "asset_name": u["asset_name"],
                       "check_number": u["check_number"], "check_title": u["check_title"],
                       "state": "not_holding" if u["verification_passed"] is False else "not_verified",
                       "at": _iso(u["at"])} for u in unverified[:LISTED]],
        },
        "not_reaudited": {
            "total": len(stale),
            "items": [{"asset_id": s["asset_id"], "asset_name": s["asset_name"], "ip_address": s["ip_address"],
                       "hardened_at": _iso(s["hardened_at"]), "audited_at": _iso(s["audited_at"])}
                      for s in stale[:LISTED]],
        },
    }


def missing(db: Session) -> List[Dict]:
    """Controls failing in each asset's latest audit with no successful fix, most assets first."""
    rows = _rows(db, """
        WITH latest AS (
            SELECT DISTINCT ON (asset_id) id, asset_id
            FROM audit_sessions
            WHERE asset_id IS NOT NULL AND status <> 'running'
            ORDER BY asset_id, started_at DESC, id DESC
        )
        SELECT r.check_number, MAX(r.check_title) AS check_title, MAX(r.severity) AS severity,
               COUNT(DISTINCT l.asset_id) AS affected_assets
        FROM audit_results r
        JOIN latest l ON l.id = r.session_id
        WHERE r.status = :fail
          AND NOT EXISTS (SELECT 1 FROM hardening_actions h
                          WHERE h.audit_result_id = r.id AND h.status = 'success')
        GROUP BY r.check_number
        ORDER BY COUNT(DISTINCT l.asset_id) DESC, r.check_number
        LIMIT :limit
    """, {"fail": CheckStatus.FAIL.name, "limit": LISTED})
    return [{**r, "affected_assets": int(r["affected_assets"]),
             "link": f"/remediation?q={r['check_number']}"} for r in rows]


def impact(db: Session, now: datetime) -> Dict:
    findings = db.execute(text(f"""
        WITH targeted AS (
            SELECT r.id, LOWER(COALESCE(r.severity, '')) AS severity, BOOL_OR(h.status = 'success') AS fixed
            FROM audit_results r JOIN hardening_actions h ON h.audit_result_id = r.id
            WHERE r.status = :fail AND {EXECUTED}
            GROUP BY r.id, LOWER(COALESCE(r.severity, ''))
        )
        SELECT COUNT(*) FILTER (WHERE fixed) AS fixed,
               COUNT(*) FILTER (WHERE fixed AND severity = 'critical') AS critical,
               COUNT(*) FILTER (WHERE fixed AND severity = 'high') AS high,
               COUNT(*) AS targeted
        FROM targeted
    """), {"fail": CheckStatus.FAIL.name}).mappings().one()
    # Risk of the assets hardened lately: the latest score before their first change, and now.
    risk = db.execute(text(f"""
        WITH first_change AS (
            SELECT h.asset_id, MIN(COALESCE(h.executed_at, h.created_at)) AS at
            FROM hardening_actions h
            WHERE {EXECUTED} AND h.status = 'success' AND COALESCE(h.executed_at, h.created_at) >= :since
            GROUP BY h.asset_id
        ), pairs AS (
            SELECT f.asset_id,
                   (SELECT r.risk_score FROM asset_risk_history r
                    WHERE r.asset_id = f.asset_id AND r.calculated_at <= f.at
                    ORDER BY r.calculated_at DESC, r.id DESC LIMIT 1) AS before,
                   s.final_risk_score AS now
            FROM first_change f JOIN asset_risk_scores s ON s.asset_id = f.asset_id
        )
        SELECT COUNT(*) AS assets, ROUND(AVG(before)::numeric, 1) AS before, ROUND(AVG(now)::numeric, 1) AS now
        FROM pairs WHERE before IS NOT NULL AND now IS NOT NULL
    """), {"since": now - timedelta(days=IMPACT_DAYS)}).mappings().one()
    assets = int(risk["assets"] or 0)
    return {
        "findings_fixed": int(findings["fixed"] or 0),
        "critical_fixed": int(findings["critical"] or 0),
        "high_fixed": int(findings["high"] or 0),
        "findings_targeted": int(findings["targeted"] or 0),
        "risk": {
            "assets": assets,
            "before": float(risk["before"]) if assets else None,
            "now": float(risk["now"]) if assets else None,
            "days": IMPACT_DAYS,
        },
    }


def coverage(db: Session) -> Dict:
    types = _rows(db, """
        SELECT a.asset_type_id AS type_id, COALESCE(t.type_name, 'Unknown') AS name, COUNT(*) AS total,
               COUNT(*) FILTER (WHERE EXISTS (
                   SELECT 1 FROM hardening_actions h
                   WHERE h.asset_id = a.id AND h.status = 'success' AND h.action_type <> 'preview')) AS hardened
        FROM asset_inventory a LEFT JOIN asset_types t ON t.id = a.asset_type_id
        GROUP BY a.asset_type_id, t.type_name
        ORDER BY COUNT(*) DESC
    """)
    levels = _rows(db, f"""
        SELECT COALESCE(NULLIF(r.level, ''), 'Unspecified') AS level,
               COUNT(*) FILTER (WHERE h.status IN ('success', 'failed')) AS done,
               COUNT(*) FILTER (WHERE h.status = 'success') AS succeeded
        FROM hardening_actions h JOIN audit_results r ON r.id = h.audit_result_id
        WHERE {EXECUTED}
        GROUP BY COALESCE(NULLIF(r.level, ''), 'Unspecified')
        ORDER BY 1
    """)
    recent = _rows(db, f"""
        SELECT h.id, h.asset_id, a.asset_name, h.check_number, h.check_title, h.status,
               COALESCE(h.executed_at, h.created_at) AS at
        FROM hardening_actions h LEFT JOIN asset_inventory a ON a.id = h.asset_id
        WHERE {EXECUTED}
        ORDER BY h.created_at DESC, h.id DESC
        LIMIT 8
    """)
    return {
        "by_type": [{"type_id": t["type_id"], "name": t["name"], "total": int(t["total"]),
                     "hardened": int(t["hardened"]), "pct": _pct(int(t["hardened"]), int(t["total"])),
                     "link": f"/assets/inventory?type={t['type_id']}" if t["type_id"] else None} for t in types],
        "by_level": [{"level": lv["level"], "done": int(lv["done"]), "succeeded": int(lv["succeeded"]),
                      "pct": _pct(int(lv["succeeded"]), int(lv["done"]))} for lv in levels],
        "recent": [{**r, "at": _iso(r["at"])} for r in recent],
    }


def overview(db: Session, user: User, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    return {
        "figures": figures(db, now),
        "attention": attention(db),
        "missing": missing(db),
        "impact": impact(db, now),
        "coverage": coverage(db),
    }
