"""
Risk Module Seed Data

Seeds default risk_settings and risk_zones. Idempotent: existing rows
(matched by setting_key / zone name) are left untouched, so operator
customizations survive re-runs.

Run directly:  python -m app.modules.risk.seed
Or call seed_risk_defaults(db) from application startup.
"""

import logging

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.risk import RiskSetting, RiskZone

logger = logging.getLogger(__name__)


DEFAULT_SETTINGS = [
    # Factor weights - spec section 4:
    #   RiskScore = (AC*0.25)+(AZ*0.20)+(OP*0.15)+(AF*0.40)
    # These four must sum to 100.
    ("criticality_weight", "25", "int", "AC: weight of asset criticality in the final risk score (%)"),
    ("zone_weight", "20", "int", "AZ: weight of network zone exposure in the final risk score (%)"),
    ("open_port_weight", "15", "int", "OP: weight of open-port exposure in the final risk score (%)"),
    ("audit_weight", "40", "int", "AF: weight of audit findings in the final risk score (%)"),
    # Computed for the breakdown but outside the spec's formula, hence 0.
    ("asset_risk_weight", "0", "int", "AR: asset's own risk level — shown in the breakdown, not weighted"),
    ("hardening_weight", "0", "int", "HF: hardening fixes found — shown in the breakdown, not weighted"),
    # Per-severity weights for audit findings and hardening fixes found
    ("severity_low_weight", "1", "int", "Finding weight for low severity"),
    ("severity_medium_weight", "3", "int", "Finding weight for medium severity"),
    ("severity_high_weight", "7", "int", "Finding weight for high severity"),
    ("severity_critical_weight", "10", "int", "Finding weight for critical severity"),
    # Per-severity weights for open ports (a different scale from findings)
    ("port_severity_low_weight", "1", "int", "Open-port points for standard/low-risk ports"),
    ("port_severity_medium_weight", "3", "int", "Open-port points for medium-risk ports"),
    ("port_severity_high_weight", "5", "int", "Open-port points for high-risk ports"),
    ("port_severity_critical_weight", "10", "int", "Open-port points for critical/insecure ports"),
    # Open-port score normalization: OP = min(100, raw_points * factor)
    ("open_port_normalization_factor", "4", "int", "Multiplier applied to the raw open-port points before the 0-100 cap"),
    # Fallback scores when input data is missing
    ("unknown_zone_score", "50", "int", "Zone score used when the asset has no zone assigned"),
    ("unknown_port_score", "50", "int", "Port score used when no port scan data exists"),
    ("unknown_audit_score", "50", "int", "Audit score used when no audit results exist"),
    ("unknown_asset_risk_score", "50", "int", "Asset-risk score used when the asset has no risk level set"),
    ("no_hardening_data_score", "0", "int", "Hardening-fix score used when the asset has no hardening data"),
    # asset_inventory.risk_level -> AR score
    ("asset_risk_low_score", "25", "int", "AR score for assets with risk level low"),
    ("asset_risk_medium_score", "50", "int", "AR score for assets with risk level medium"),
    ("asset_risk_high_score", "75", "int", "AR score for assets with risk level high"),
    ("asset_risk_very_high_score", "90", "int", "AR score for assets with the legacy risk level very_high"),
    ("asset_risk_critical_score", "100", "int", "AR score for assets with risk level critical"),
    # Behavior flags
    ("include_warning_in_audit_risk", "false", "bool", "Whether warning-level audit findings count toward audit risk"),
    # Organization security-score sub-score weights (must sum to 100) -
    # consumed by app/modules/dashboard/security_score_router.py
    ("security_asset_health_weight", "20", "int", "Security score: weight of asset health (active/total assets) (%)"),
    ("security_audit_compliance_weight", "20", "int", "Security score: weight of audit compliance (passed/applicable controls) (%)"),
    ("security_hardening_weight", "20", "int", "Security score: weight of hardening success (verified fixes/attempts) (%)"),
    ("security_risk_intelligence_weight", "20", "int", "Security score: weight of inverted average asset risk (%)"),
    ("security_exposure_intelligence_weight", "10", "int", "Security score: weight of inverted open-port exposure (%)"),
    ("security_vulnerability_weight", "10", "int", "Security score: weight of inverted vulnerability assessment (%)"),
    # NOTE: the criticality level->score mapping (criticality_*_score) and the
    # risk-level thresholds (risk_level_*_threshold) are NOT seeded here. They
    # are owned by Alembic migrations d4f6a8b0c2e1 (20260813_add_missing_risk_settings)
    # and e5c1a7d93b48 (20260818_risk_six_factor_formula), which run as part of
    # `alembic upgrade head` on every deploy. Keeping them in one place avoids
    # two sources of truth for the same rows.
]

DEFAULT_ZONES = [
    ("Management/Restricted", 20, "Isolated management network with tightly restricted access"),
    ("Internal User Zone", 35, "Internal end-user workstation network"),
    ("Internal Server Zone", 50, "Internal server network"),
    ("Partner/Extranet", 65, "Network segments shared with partners or extranet services"),
    ("DMZ", 80, "Demilitarized zone hosting externally reachable services"),
    ("Internet/Public", 100, "Directly internet-facing / public network"),
    ("Unknown", 50, "Default zone when the real network zone is not known"),
]


def seed_risk_defaults(db: Session) -> dict:
    """Insert missing default risk settings and zones. Returns counts of rows added."""
    settings_added = 0
    for key, value, value_type, description in DEFAULT_SETTINGS:
        exists = db.query(RiskSetting).filter(RiskSetting.setting_key == key).first()
        if exists:
            continue
        db.add(
            RiskSetting(
                setting_key=key,
                setting_value=value,
                value_type=value_type,
                description=description,
                is_editable=True,
            )
        )
        settings_added += 1

    zones_added = 0
    for name, score, description in DEFAULT_ZONES:
        exists = db.query(RiskZone).filter(RiskZone.name == name).first()
        if exists:
            continue
        db.add(
            RiskZone(
                name=name,
                score=score,
                description=description,
                status="active",
            )
        )
        zones_added += 1

    db.commit()
    logger.info(
        "Risk seed: %d settings added, %d zones added", settings_added, zones_added
    )
    return {"settings_added": settings_added, "zones_added": zones_added}


def main():
    logging.basicConfig(level=logging.INFO)
    db = SessionLocal()
    try:
        result = seed_risk_defaults(db)
        print(
            f"Seed complete: {result['settings_added']} settings added, "
            f"{result['zones_added']} zones added"
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
