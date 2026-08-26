"""risk: restore the PDF six-factor formula values (weights, severity, zones, levels)

Reverts the four-factor reweighting from f9d2b6e41a73 back to the values defined
by the NGCorion Risk Score Calculation Specification (risk.pdf), which is the
single source of truth:

    RiskScore = AC*0.20 + AR*0.20 + AZ*0.15 + OP*0.10 + AF*0.25 + HF*0.10

Changes (all data-only; the risk_settings columns already exist):

1. risk_settings — factor weights 20/20/15/10/25/10, finding medium weight 4
   (PDF 7/8), open-port normalization factor 1 so OP = min(100, sum) (PDF 6).
   Level thresholds stay 20/40/60/80 (PDF 10). AR/HF weight rows are ensured
   present (they were added by e5c1a7d93b48; INSERT ... ON CONFLICT DO NOTHING).

2. risk_zones — upsert the PDF exposure scores by name (PDF 5): Isolated/Lab 10,
   Management 20, Internal Server Zone 40, User Network 50, DMZ 80,
   Internet/Public 100. Legacy operator/seed zones with other names are left
   untouched.

3. Re-derive the stored risk_level text in asset_risk_scores / asset_risk_history
   from the stored score under the PDF bands
   (0-20 informational | 21-40 low | 41-60 medium | 61-80 high | 81-100 critical).

After upgrading, run POST /api/risk/recalculate-all so the per-component columns
are refreshed under the six-factor weights (the level text re-derivation here
only keeps the stored bands consistent until then).

Revision ID: b3f7c1d9e2a4
Revises: f9d2b6e41a73
Create Date: 2026-08-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b3f7c1d9e2a4'
down_revision: Union[str, Sequence[str], None] = 'f9d2b6e41a73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (setting_key, PDF value, previous value used by f9d2b6e41a73)
_SETTINGS = [
    ("criticality_weight", "20", "25"),
    ("asset_risk_weight", "20", "0"),
    ("zone_weight", "15", "20"),
    ("open_port_weight", "10", "15"),
    ("audit_weight", "25", "40"),
    ("hardening_weight", "10", "0"),
    ("severity_medium_weight", "4", "3"),
    ("open_port_normalization_factor", "1", "4"),
]

# Keys the six-factor formula relies on that may be missing on very old DBs.
_ENSURE_SETTINGS = [
    ("asset_risk_weight", "20", "int",
     "AR: weight of the asset's own risk level in the final risk score (%)"),
    ("hardening_weight", "10", "int",
     "HF: weight of hardening fixes found in the final risk score (%)"),
]

# PDF section 5 exposure scores, upserted by name.
_ZONES = [
    ("Isolated / Lab", "10", "Isolated or lab network with no production exposure"),
    ("Management", "20", "Restricted management network"),
    ("Internal Server Zone", "40", "Internal server network"),
    ("User Network", "50", "Internal end-user workstation network"),
    ("DMZ", "80", "Demilitarized zone hosting externally reachable services"),
    ("Internet / Public", "100", "Directly internet-facing / public network"),
]

# PDF bands (exclusive lower bounds); stored level derived from stored score.
_PDF_LEVEL_CASE = """
    CASE
        WHEN {col} IS NULL THEN risk_level
        WHEN {col} > 80 THEN 'critical'
        WHEN {col} > 60 THEN 'high'
        WHEN {col} > 40 THEN 'medium'
        WHEN {col} > 20 THEN 'low'
        ELSE 'informational'
    END
"""

# Pre-revision (four-factor) bands, for downgrade().
_OLD_LEVEL_CASE = """
    CASE
        WHEN {col} IS NULL THEN risk_level
        WHEN {col} >= 80 THEN 'critical'
        WHEN {col} >= 60 THEN 'very_high'
        WHEN {col} >= 40 THEN 'high'
        WHEN {col} >= 20 THEN 'medium'
        ELSE 'low'
    END
"""


def _set_settings(pairs) -> None:
    bind = op.get_bind()
    for key, value in pairs:
        bind.execute(
            sa.text(
                "UPDATE risk_settings SET setting_value = :value, "
                "updated_at = NOW() WHERE setting_key = :key"
            ),
            {"key": key, "value": value},
        )


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Settings: restore PDF weights / severity / normalization
    _set_settings([(key, value) for key, value, _ in _SETTINGS])
    for key, value, value_type, description in _ENSURE_SETTINGS:
        bind.execute(
            sa.text(
                "INSERT INTO risk_settings "
                "(setting_key, setting_value, value_type, description, "
                " is_editable, created_at, updated_at) "
                "VALUES (:key, :value, :value_type, :description, TRUE, "
                " NOW(), NOW()) "
                "ON CONFLICT (setting_key) DO NOTHING"
            ),
            {"key": key, "value": value, "value_type": value_type,
             "description": description},
        )

    # 2. Zones: upsert the PDF exposure scores by name
    for name, score, description in _ZONES:
        bind.execute(
            sa.text(
                "INSERT INTO risk_zones "
                "(name, description, score, status, created_at, updated_at) "
                "VALUES (:name, :description, :score, 'active', NOW(), NOW()) "
                "ON CONFLICT (name) DO UPDATE SET "
                "  score = EXCLUDED.score, updated_at = NOW()"
            ),
            {"name": name, "description": description, "score": score},
        )

    # 3. Re-derive stored levels from stored scores under the PDF bands
    bind.execute(sa.text(
        "UPDATE asset_risk_scores SET risk_level = "
        + _PDF_LEVEL_CASE.format(col="final_risk_score")
    ))
    bind.execute(sa.text(
        "UPDATE asset_risk_history SET risk_level = "
        + _PDF_LEVEL_CASE.format(col="risk_score")
    ))


def downgrade() -> None:
    bind = op.get_bind()

    # 3. Levels back to the four-factor bands
    bind.execute(sa.text(
        "UPDATE asset_risk_history SET risk_level = "
        + _OLD_LEVEL_CASE.format(col="risk_score")
    ))
    bind.execute(sa.text(
        "UPDATE asset_risk_scores SET risk_level = "
        + _OLD_LEVEL_CASE.format(col="final_risk_score")
    ))

    # 1. Settings back to the four-factor values. Zones are operator-managed
    #    reference data and are left as-is on downgrade.
    _set_settings([(key, previous) for key, _, previous in _SETTINGS])
