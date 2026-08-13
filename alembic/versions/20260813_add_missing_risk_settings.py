"""add missing risk settings (criticality scores + level thresholds)

Revision ID: d4f6a8b0c2e1
Revises: f1a2b3c4d5e6
Create Date: 2026-08-13 00:00:00.000000

Idempotent DATA migration (no schema change). Inserts the eight ``risk_settings``
rows that the risk engine reads for the criticality level->score mapping and the
risk-level thresholds. These were previously only present in
``app/modules/risk/service.DEFAULT_SETTINGS`` (code fallbacks) and in the manual
seed script, so they were invisible/uneditable via ``GET/PUT /api/risk/settings``
in any environment where the seed had not been run. Owning them here means
``alembic upgrade head`` guarantees they exist.

Insert uses PostgreSQL ``ON CONFLICT (setting_key) DO NOTHING`` so re-running the
migration (or running it against a DB where the seed already inserted the rows)
is a no-op and never clobbers operator customizations.
"""
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'd4f6a8b0c2e1'
down_revision: Union[str, Sequence[str], None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (setting_key, setting_value, value_type, description) — is_editable is True for
# all. Values mirror service.DEFAULT_SETTINGS and the seed defaults.
_ROWS = [
    ("criticality_low_score", "25", "int", "Score for low-criticality assets"),
    ("criticality_medium_score", "50", "int", "Score for medium-criticality assets"),
    ("criticality_high_score", "75", "int", "Score for high-criticality assets"),
    ("criticality_critical_score", "100", "int", "Score for critical assets"),
    ("risk_level_medium_threshold", "20", "int", "Lower bound of the Medium risk level"),
    ("risk_level_high_threshold", "40", "int", "Lower bound of the High risk level"),
    ("risk_level_very_high_threshold", "60", "int", "Lower bound of the Very High risk level"),
    ("risk_level_critical_threshold", "80", "int", "Lower bound of the Critical risk level"),
]

_SETTING_KEYS = [row[0] for row in _ROWS]

# Lightweight Core table bound to the migration connection — deliberately NOT the
# ORM model, so this migration stays independent of application imports.
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


def upgrade() -> None:
    """Insert the 8 settings rows if they don't already exist."""
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
        for key, value, value_type, description in _ROWS
    ]
    stmt = (
        postgresql.insert(_risk_settings)
        .values(values)
        .on_conflict_do_nothing(index_elements=["setting_key"])
    )
    op.get_bind().execute(stmt)


def downgrade() -> None:
    """Remove exactly the 8 settings rows this migration inserted."""
    op.get_bind().execute(
        _risk_settings.delete().where(
            _risk_settings.c.setting_key.in_(_SETTING_KEYS)
        )
    )
