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
    # Factor weights (must sum to 100)
    ("criticality_weight", "25", "int", "Weight of asset criticality in the final risk score (%)"),
    ("zone_weight", "20", "int", "Weight of network zone exposure in the final risk score (%)"),
    ("open_port_weight", "15", "int", "Weight of open-port exposure in the final risk score (%)"),
    ("audit_weight", "40", "int", "Weight of audit findings in the final risk score (%)"),
    # Per-severity weights for port/finding scoring
    ("severity_low_weight", "1", "int", "Score weight for low-severity items"),
    ("severity_medium_weight", "3", "int", "Score weight for medium-severity items"),
    ("severity_high_weight", "7", "int", "Score weight for high-severity items"),
    ("severity_critical_weight", "10", "int", "Score weight for critical-severity items"),
    # Open-port score normalization
    ("open_port_normalization_factor", "4", "int", "Divisor used to normalize the raw open-port score to 0-100"),
    # Fallback scores when input data is missing
    ("unknown_zone_score", "50", "int", "Zone score used when the asset has no zone assigned"),
    ("unknown_port_score", "50", "int", "Port score used when no port scan data exists"),
    ("unknown_audit_score", "50", "int", "Audit score used when no audit results exist"),
    # Behavior flags
    ("include_warning_in_audit_risk", "false", "bool", "Whether warning-level audit findings count toward audit risk"),
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
