"""
Organization Security Score API

Read-only endpoint backing the executive "security score" tile: a single
0-100 number for the whole organization, built from six independently
weighted sub-scores. Everything is derived from data other modules already
write (asset_inventory, audit_sessions/audit_results, hardening_actions,
asset_risk_scores, asset_security_status) - no new tables, no writes.

The six weights live in the existing risk_settings table under `security_*`
keys (seeded by app/modules/risk/seed.py), so operators tune them in the same
place as the risk-formula weights.

Every sub-score is "higher is better", so the risk-shaped inputs (risk score,
open-port exposure, CVSS) are inverted. A sub-score with no data behind it
falls back to UNKNOWN_SCORE (50) and marks itself incomplete, which also
raises the top-level `incomplete_data` flag - the same convention the risk
module uses for its `unknown_*` settings.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User
from app.models.asset import Asset
from app.models.asset_security_status import AssetSecurityStatus
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.enums import StatusEnum
from app.models.hardening import HardeningAction
from app.models.risk import AssetRiskScore, RiskSetting

logger = logging.getLogger(__name__)

router = APIRouter()

# Score used when a sub-score has no data behind it at all ("unknown", not "bad").
UNKNOWN_SCORE = 50.0

# risk_settings key -> default weight (%). The six must sum to 100.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "security_asset_health_weight": 20.0,
    "security_audit_compliance_weight": 20.0,
    "security_hardening_weight": 20.0,
    "security_risk_intelligence_weight": 20.0,
    "security_exposure_intelligence_weight": 10.0,
    "security_vulnerability_weight": 10.0,
}

# Response order of the sub-scores: (api key, risk_settings weight key).
SUB_SCORE_KEYS: Tuple[Tuple[str, str], ...] = (
    ("asset_health", "security_asset_health_weight"),
    ("audit_compliance", "security_audit_compliance_weight"),
    ("hardening", "security_hardening_weight"),
    ("risk_intelligence", "security_risk_intelligence_weight"),
    ("exposure_intelligence", "security_exposure_intelligence_weight"),
    ("vulnerability", "security_vulnerability_weight"),
)

# Exclusive lower bound of each level, evaluated highest to lowest:
#   0-40 critical | 41-60 poor | 61-75 fair | 76-90 good | 91-100 excellent
SCORE_LEVEL_BANDS: Tuple[Tuple[float, str], ...] = (
    (90.0, "excellent"),
    (75.0, "good"),
    (60.0, "fair"),
    (40.0, "poor"),
)

# A sub-score result: (score 0-100, reason when incomplete else None, detail).
SubScore = Tuple[float, Optional[str], Dict[str, Any]]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


def _pct(part: float, whole: float) -> float:
    """part/whole as a 0-100 percentage; 0 when there is nothing to divide."""
    return round(100.0 * part / whole, 2) if whole else 0.0


def _load_weights(db: Session) -> Dict[str, float]:
    """The six weights from risk_settings, falling back to DEFAULT_WEIGHTS."""
    weights = dict(DEFAULT_WEIGHTS)
    rows = (
        db.query(RiskSetting)
        .filter(RiskSetting.setting_key.in_(tuple(DEFAULT_WEIGHTS)))
        .all()
    )
    for row in rows:
        try:
            weights[row.setting_key] = float(row.setting_value)
        except (TypeError, ValueError) as e:
            logger.warning(
                f"[SecurityScore] setting {row.setting_key} has unparseable "
                f"value {row.setting_value!r}, using default "
                f"{DEFAULT_WEIGHTS[row.setting_key]}: {e}"
            )
    return weights


def _score_level(score: float) -> str:
    for lower_bound, level in SCORE_LEVEL_BANDS:
        if score > lower_bound:
            return level
    return "critical"


def _latest_session_ids(db: Session) -> List[int]:
    """The newest finished audit session per asset (one session id per asset)."""
    newest = (
        db.query(
            AuditSession.asset_id.label("asset_id"),
            func.max(AuditSession.started_at).label("started_at"),
        )
        .filter(
            AuditSession.asset_id.isnot(None),
            AuditSession.status != "running",
        )
        .group_by(AuditSession.asset_id)
        .subquery()
    )
    # max(id) breaks ties when one asset has two sessions on the same timestamp.
    rows = (
        db.query(func.max(AuditSession.id))
        .join(
            newest,
            and_(
                AuditSession.asset_id == newest.c.asset_id,
                AuditSession.started_at == newest.c.started_at,
            ),
        )
        .group_by(AuditSession.asset_id)
        .all()
    )
    return [row[0] for row in rows]


# ----------------------------------------------------------------------
# Sub-scores (each returns score, incomplete-reason, detail)
# ----------------------------------------------------------------------

def _asset_health(db: Session) -> SubScore:
    """1. Asset Health: active assets / total assets."""
    total = db.query(func.count(Asset.id)).scalar() or 0
    if not total:
        return UNKNOWN_SCORE, "no assets in inventory", {
            "active_assets": 0, "total_assets": 0,
        }

    active = (
        db.query(func.count(Asset.id))
        .filter(Asset.status == StatusEnum.ACTIVE)
        .scalar()
    ) or 0
    return _pct(active, total), None, {
        "active_assets": int(active), "total_assets": int(total),
    }


def _audit_compliance(db: Session) -> SubScore:
    """2. Audit Compliance: passed / applicable controls of each asset's newest
    audit session, averaged across assets. NOT_APPLICABLE and ERROR results are
    not applicable controls, matching how the risk module weighs audits."""
    session_ids = _latest_session_ids(db)
    if not session_ids:
        return UNKNOWN_SCORE, "no completed audit sessions", {
            "assets_with_audit": 0,
        }

    rows = (
        db.query(
            AuditResult.session_id.label("session_id"),
            func.count(AuditResult.id).label("applicable"),
            func.count(AuditResult.id)
            .filter(AuditResult.status == CheckStatus.PASS)
            .label("passed"),
        )
        .filter(
            AuditResult.session_id.in_(session_ids),
            AuditResult.status.notin_(
                (CheckStatus.NOT_APPLICABLE, CheckStatus.ERROR)
            ),
        )
        .group_by(AuditResult.session_id)
        .all()
    )

    per_asset = [
        100.0 * row.passed / row.applicable for row in rows if row.applicable
    ]
    detail = {
        "assets_with_audit": len(per_asset),
        "passed_controls": int(sum(row.passed for row in rows)),
        "applicable_controls": int(sum(row.applicable for row in rows)),
    }
    if not per_asset:
        return UNKNOWN_SCORE, "no applicable audit controls", detail

    return round(sum(per_asset) / len(per_asset), 2), None, detail


def _hardening(db: Session) -> SubScore:
    """3. Hardening: verified successful fixes / hardening attempts. Previews
    are not attempts - nothing was applied to the device."""
    row = (
        db.query(
            func.count(HardeningAction.id).label("attempts"),
            func.count(HardeningAction.id)
            .filter(
                HardeningAction.status == "success",
                HardeningAction.verification_passed.is_(True),
            )
            .label("verified"),
        )
        .filter(HardeningAction.action_type != "preview")
        .first()
    )
    attempts = int(row.attempts or 0)
    verified = int(row.verified or 0)
    detail = {"verified_fixes": verified, "hardening_attempts": attempts}
    if not attempts:
        return UNKNOWN_SCORE, "no hardening actions executed", detail

    return _pct(verified, attempts), None, detail


def _risk_intelligence(db: Session) -> SubScore:
    """4. Risk Intelligence: inverted average final risk score."""
    row = (
        db.query(
            func.avg(AssetRiskScore.final_risk_score),
            func.count(AssetRiskScore.id),
        )
        .filter(AssetRiskScore.final_risk_score.isnot(None))
        .first()
    )
    average, scored = (row[0], int(row[1] or 0)) if row else (None, 0)
    if average is None:
        return UNKNOWN_SCORE, "no assets have a risk score yet", {
            "scored_assets": 0,
        }

    return _clamp(round(100.0 - float(average), 2)), None, {
        "scored_assets": scored,
        "avg_risk_score": round(float(average), 2),
    }


def _exposure_intelligence(db: Session) -> SubScore:
    """5. Exposure Intelligence: inverted average open-port risk score."""
    row = (
        db.query(
            func.avg(AssetRiskScore.open_port_score),
            func.count(AssetRiskScore.id),
        )
        .filter(AssetRiskScore.open_port_score.isnot(None))
        .first()
    )
    average, scored = (row[0], int(row[1] or 0)) if row else (None, 0)
    if average is None:
        return UNKNOWN_SCORE, "no open-port exposure data", {"scored_assets": 0}

    return _clamp(round(100.0 - float(average), 2)), None, {
        "scored_assets": scored,
        "avg_open_port_score": round(float(average), 2),
    }


def _vulnerability(db: Session) -> SubScore:
    """6. Vulnerability: inverted average of asset_security_status.
    vulnerability_score (0-10 CVSS-style, so x10 to reach the 0-100 scale).

    There is no vulnerability scanner in the product yet; until one lands this
    is whatever operators recorded by hand, and an empty table means unknown
    (50) rather than perfect.
    """
    row = (
        db.query(
            func.avg(AssetSecurityStatus.vulnerability_score),
            func.count(AssetSecurityStatus.id),
        )
        .filter(AssetSecurityStatus.vulnerability_score.isnot(None))
        .first()
    )
    average, assessed = (row[0], int(row[1] or 0)) if row else (None, 0)
    if average is None:
        return UNKNOWN_SCORE, "no vulnerability data", {"assessed_assets": 0}

    return _clamp(round(100.0 - float(average) * 10.0, 2)), None, {
        "assessed_assets": assessed,
        "avg_vulnerability_score": round(float(average), 2),
    }


SUB_SCORE_FUNCS = {
    "asset_health": _asset_health,
    "audit_compliance": _audit_compliance,
    "hardening": _hardening,
    "risk_intelligence": _risk_intelligence,
    "exposure_intelligence": _exposure_intelligence,
    "vulnerability": _vulnerability,
}


# ----------------------------------------------------------------------
# Endpoint
# ----------------------------------------------------------------------

@router.get("/security-score")
def security_score(
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """Organization-wide security score (0-100) and its six sub-scores."""
    weights = _load_weights(db)

    sub_scores: Dict[str, Dict[str, Any]] = {}
    incomplete_reasons: List[str] = []
    total = 0.0

    for key, weight_key in SUB_SCORE_KEYS:
        try:
            score, reason, detail = SUB_SCORE_FUNCS[key](db)
        except Exception as e:
            # One broken sub-query degrades that sub-score instead of 500-ing
            # the whole dashboard tile.
            logger.warning(f"[SecurityScore] sub-score {key} failed: {e}")
            score, reason, detail = UNKNOWN_SCORE, f"{key} calculation failed", {}

        weight = weights[weight_key]
        contribution = score * weight / 100.0
        total += contribution

        entry: Dict[str, Any] = {
            "score": round(score, 2),
            "weight": round(weight, 2),
            "contribution": round(contribution, 2),
        }
        if detail:
            entry["detail"] = detail
        if reason:
            entry["incomplete"] = True
            incomplete_reasons.append(f"{key}: {reason}")
        sub_scores[key] = entry

    final_score = round(_clamp(total), 2)
    return {
        "security_score": final_score,
        "score_level": _score_level(final_score),
        "sub_scores": sub_scores,
        "incomplete_data": bool(incomplete_reasons),
        "incomplete_reasons": incomplete_reasons,
    }
