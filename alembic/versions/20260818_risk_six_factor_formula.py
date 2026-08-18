"""risk: six-factor formula (add AR + HF, reweight, new risk levels)

Revision ID: e5c1a7d93b48
Revises: c7e1b93a5d02
Create Date: 2026-08-18

Moves the risk engine from the four-factor score to the six-factor one:

    RiskScore = (AC*0.20)+(AR*0.20)+(AZ*0.15)+(OP*0.10)+(AF*0.25)+(HF*0.10)

Three things change here:

1. SCHEMA - asset_risk_scores and asset_risk_history gain the AR (asset's own
   asset_inventory.risk_level) and HF (hardening fixes found) component
   columns, mirroring the existing per-factor score/weight/contribution
   layout. All nullable, so the migration is safe on a populated table; the
   next calculation fills them in.

2. DATA (risk_settings) - factor weights, the finding severity scale
   (medium 3 -> 4), the new open-port severity scale (high 7 -> 5, kept in its
   own port_severity_* keys), the AR level->score map, the HF fallback and the
   re-banded level thresholds. Unlike d4f6a8b0c2e1, this migration *updates*
   existing rows for the keys the new formula redefines - the old values are
   arithmetically incompatible with it (they no longer sum to 100). New keys
   are inserted with ON CONFLICT DO NOTHING.

3. DATA (risk_level) - the level bands changed
   (0-20 informational | 21-40 low | 41-60 medium | 61-80 high | 81-100 critical),
   so 'very_high' no longer exists. Stored levels in asset_risk_scores and
   asset_risk_history are re-derived from their stored score rather than
   text-mapped, which keeps them consistent until the next recalculation.
   Note the component columns still hold four-factor values until then; run
   POST /api/risk/recalculate-all after upgrading.
"""
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e5c1a7d93b48'
down_revision: Union[str, Sequence[str], None] = 'c7e1b93a5d02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# --- new columns -------------------------------------------------------

_SCORE_COLUMNS = [
    ("asset_risk_level", sa.String(length=30)),
    ("asset_risk_score", sa.Numeric(5, 2)),
    ("asset_risk_weight", sa.Numeric(5, 2)),
    ("asset_risk_contribution", sa.Numeric(5, 2)),
    ("hardening_fix_raw_score", sa.Numeric(8, 2)),
    ("hardening_applicable_weight", sa.Numeric(8, 2)),
    ("hardening_fix_score", sa.Numeric(5, 2)),
    ("hardening_weight", sa.Numeric(5, 2)),
    ("hardening_contribution", sa.Numeric(5, 2)),
]

_HISTORY_COLUMNS = [
    ("asset_risk_score", sa.Numeric(5, 2)),
    ("asset_risk_contribution", sa.Numeric(5, 2)),
    ("hardening_fix_score", sa.Numeric(5, 2)),
    ("hardening_contribution", sa.Numeric(5, 2)),
]

# --- settings ----------------------------------------------------------

# Keys the new formula redefines: (key, new_value, value_type, description).
# Applied with UPDATE ... then INSERT ... ON CONFLICT DO NOTHING, so a fresh
# database and an existing one converge on the same values.
_UPDATED_SETTINGS = [
    ("criticality_weight", "20", "int",
     "AC: weight of asset criticality in the final risk score (%)"),
    ("zone_weight", "15", "int",
     "AZ: weight of network zone exposure in the final risk score (%)"),
    ("open_port_weight", "10", "int",
     "OP: weight of open-port exposure in the final risk score (%)"),
    ("audit_weight", "25", "int",
     "AF: weight of audit findings in the final risk score (%)"),
    ("severity_medium_weight", "4", "int", "Finding weight for medium severity"),
    ("severity_low_weight", "1", "int", "Finding weight for low severity"),
    ("severity_high_weight", "7", "int", "Finding weight for high severity"),
    ("severity_critical_weight", "10", "int", "Finding weight for critical severity"),
    # OP is now min(100, sum of port points): no extra normalization multiplier
    ("open_port_normalization_factor", "1", "int",
     "Multiplier applied to the raw open-port points before the 0-100 cap"),
    # Re-banded thresholds (exclusive lower bounds)
    ("risk_level_medium_threshold", "40", "int", "Lower bound of the Medium risk level"),
    ("risk_level_high_threshold", "60", "int", "Lower bound of the High risk level"),
    ("risk_level_critical_threshold", "80", "int", "Lower bound of the Critical risk level"),
]

# Keys the six-factor formula adds.
_NEW_SETTINGS = [
    ("asset_risk_weight", "20", "int",
     "AR: weight of the asset's own risk level in the final risk score (%)"),
    ("hardening_weight", "10", "int",
     "HF: weight of hardening fixes found in the final risk score (%)"),
    ("port_severity_low_weight", "1", "int",
     "Open-port points for standard/low-risk ports"),
    ("port_severity_medium_weight", "3", "int",
     "Open-port points for medium-risk ports"),
    ("port_severity_high_weight", "5", "int",
     "Open-port points for high-risk ports"),
    ("port_severity_critical_weight", "10", "int",
     "Open-port points for critical/insecure ports"),
    ("unknown_asset_risk_score", "50", "int",
     "Asset-risk score used when the asset has no risk level set"),
    ("no_hardening_data_score", "0", "int",
     "Hardening-fix score used when the asset has no hardening data"),
    ("asset_risk_low_score", "25", "int", "AR score for assets with risk level low"),
    ("asset_risk_medium_score", "50", "int", "AR score for assets with risk level medium"),
    ("asset_risk_high_score", "75", "int", "AR score for assets with risk level high"),
    ("asset_risk_very_high_score", "90", "int",
     "AR score for assets with the legacy risk level very_high"),
    ("asset_risk_critical_score", "100", "int",
     "AR score for assets with risk level critical"),
    ("risk_level_low_threshold", "20", "int", "Lower bound of the Low risk level"),
]

# Values restored by downgrade() for keys that existed before this revision.
_PREVIOUS_SETTINGS = [
    ("criticality_weight", "25"),
    ("zone_weight", "20"),
    ("open_port_weight", "15"),
    ("audit_weight", "40"),
    ("severity_medium_weight", "3"),
    ("open_port_normalization_factor", "4"),
    ("risk_level_medium_threshold", "20"),
    ("risk_level_high_threshold", "40"),
    ("risk_level_critical_threshold", "80"),
]

_risk_settings = sa.table(
    "risk_settings",
    sa.column("setting_key", sa.String),
    sa.column("setting_value", sa.String),
    sa.column("value_type", sa.String),
    sa.column("description", sa.String),
    sa.column("is_editable", sa.Boolean),
    sa.column("created_at", sa.DateTime),
    sa.column("updated_at", sa.DateTime),
)

# 0-20 informational | 21-40 low | 41-60 medium | 61-80 high | 81-100 critical
_NEW_LEVEL_CASE = """
    CASE
        WHEN {col} IS NULL THEN risk_level
        WHEN {col} > 80 THEN 'critical'
        WHEN {col} > 60 THEN 'high'
        WHEN {col} > 40 THEN 'medium'
        WHEN {col} > 20 THEN 'low'
        ELSE 'informational'
    END
"""

# Pre-revision bands, for downgrade()
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


def _insert_settings(rows) -> None:
    """Insert setting rows, skipping keys that already exist."""
    now = datetime.utcnow()
    values = [
        {
            "setting_key": key,
            "setting_value": value,
            "value_type": value_type,
            "description": description,
            "is_editable": True,
            "created_at": now,
            "updated_at": now,
        }
        for key, value, value_type, description in rows
    ]
    stmt = postgresql.insert(_risk_settings).values(values)
    op.get_bind().execute(
        stmt.on_conflict_do_nothing(index_elements=["setting_key"])
    )


def upgrade() -> None:
    # 1. Schema: AR + HF component columns
    for name, type_ in _SCORE_COLUMNS:
        op.add_column("asset_risk_scores", sa.Column(name, type_, nullable=True))
    op.add_column(
        "asset_risk_scores",
        sa.Column(
            "hardening_fixes_found_count", sa.Integer(),
            nullable=False, server_default="0",
        ),
    )
    for name, type_ in _HISTORY_COLUMNS:
        op.add_column("asset_risk_history", sa.Column(name, type_, nullable=True))

    bind = op.get_bind()

    # 2. Settings: reweight existing keys, then add the new ones
    for key, value, value_type, description in _UPDATED_SETTINGS:
        bind.execute(
            sa.text(
                "UPDATE risk_settings "
                "SET setting_value = :value, value_type = :value_type, "
                "    description = :description, updated_at = NOW() "
                "WHERE setting_key = :key"
            ),
            {"key": key, "value": value, "value_type": value_type,
             "description": description},
        )
    _insert_settings(_UPDATED_SETTINGS)
    _insert_settings(_NEW_SETTINGS)

    # 'very_high' is no longer a band; drop its threshold row so
    # GET /api/risk/settings stops advertising a key nothing reads.
    bind.execute(
        sa.text(
            "DELETE FROM risk_settings "
            "WHERE setting_key = 'risk_level_very_high_threshold'"
        )
    )

    # 3. Re-derive stored levels from stored scores under the new bands
    bind.execute(sa.text(
        "UPDATE asset_risk_scores SET risk_level = "
        + _NEW_LEVEL_CASE.format(col="final_risk_score")
    ))
    bind.execute(sa.text(
        "UPDATE asset_risk_history SET risk_level = "
        + _NEW_LEVEL_CASE.format(col="risk_score")
    ))


def downgrade() -> None:
    bind = op.get_bind()

    # 3. Levels back to the pre-revision bands
    bind.execute(sa.text(
        "UPDATE asset_risk_history SET risk_level = "
        + _OLD_LEVEL_CASE.format(col="risk_score")
    ))
    bind.execute(sa.text(
        "UPDATE asset_risk_scores SET risk_level = "
        + _OLD_LEVEL_CASE.format(col="final_risk_score")
    ))

    # 2. Settings: drop the six-factor keys, restore the four-factor values
    keys = [key for key, _, _, _ in _NEW_SETTINGS]
    bind.execute(
        sa.text("DELETE FROM risk_settings WHERE setting_key = ANY(:keys)"),
        {"keys": keys},
    )
    for key, value in _PREVIOUS_SETTINGS:
        bind.execute(
            sa.text(
                "UPDATE risk_settings SET setting_value = :value, updated_at = NOW() "
                "WHERE setting_key = :key"
            ),
            {"key": key, "value": value},
        )
    _insert_settings([
        ("risk_level_very_high_threshold", "60", "int",
         "Lower bound of the Very High risk level"),
    ])

    # 1. Schema
    for name, _ in _HISTORY_COLUMNS:
        op.drop_column("asset_risk_history", name)
    op.drop_column("asset_risk_scores", "hardening_fixes_found_count")
    for name, _ in _SCORE_COLUMNS:
        op.drop_column("asset_risk_scores", name)
