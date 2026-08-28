"""Align risk levels with the spec's five bands; drop the very_high AR tier.

The NGCorion Risk Score Calculation Specification (section 10) defines
exactly five risk levels with gapped integer bounds:

    0-20 Informational | 21-40 Low | 41-60 Medium | 61-80 High | 81-100 Critical

The engine instead emitted a different five-level scheme -- low/medium/high/
very_high/critical, with continuous bounds at 20/40/60/80 -- kept from an
earlier client requirement (see revision a4c7e1b90d52). That requirement no
longer stands: the spec is now the source of truth, so this revision:

1. rewrites the four ``risk_level_*_threshold`` rows in ``risk_settings``
   from the old scheme's keys/values (medium=20, high=40, very_high=60,
   critical=80) to the spec's (low=21, medium=41, high=61, critical=81),
   dropping the now-retired ``risk_level_very_high_threshold`` key. A table
   already on non-default values is reset to the spec defaults rather than
   guessing how to carry a custom offset across the rename -- this is a
   one-time alignment to a newly-authoritative spec, not a routine settings
   change;
2. re-derives ``risk_level`` in ``asset_risk_scores`` and ``asset_risk_history``
   from the stored score under those bounds, so no row keeps a level the
   current rule (app/modules/risk/levels.py) would not produce;
3. drops the ``asset_risk_very_high_score`` settings row: the spec's Asset
   Risk table (section 4) has exactly four tiers, and an asset classified
   "very_high" is now scored via the unknown_asset_risk_score fallback (see
   AssetRiskCalculationService._AR_RECOGNIZED_LEVELS) rather than a fifth,
   undocumented score. This is a risk_settings *data* row, not a schema
   change -- asset_inventory.risk_level's Postgres enum is untouched, so any
   asset already classified "very_high" keeps that value and simply scores
   as AR-unknown until its classification is corrected.

Revision ID: e8f2a1c9b6d3
Revises: c3a91f57d8b4
"""
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'e8f2a1c9b6d3'
down_revision: Union[str, Sequence[str], None] = 'c3a91f57d8b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Band -> (new setting key, spec default lower bound). Mirrors
# app/modules/risk/levels.py::LEVEL_THRESHOLD_KEYS; restated here because a
# migration must keep working against the schema of its own moment, not
# whatever the application code says later.
_NEW_BANDS = (
    ("low", "risk_level_low_threshold", 21),
    ("medium", "risk_level_medium_threshold", 41),
    ("high", "risk_level_high_threshold", 61),
    ("critical", "risk_level_critical_threshold", 81),
)

# The old scheme's keys, in the same band order, for downgrade() and for
# detecting whether this revision has already run.
_OLD_BANDS = (
    ("low", "risk_level_medium_threshold", 20),
    ("medium", "risk_level_high_threshold", 40),
    ("high", "risk_level_very_high_threshold", 60),
    ("critical", "risk_level_critical_threshold", 80),
)

_RETIRED_KEY = "risk_level_very_high_threshold"
_RETIRED_AR_KEY = "asset_risk_very_high_score"

_NEW_DESCRIPTIONS = {
    "risk_level_low_threshold": "Inclusive lower bound of the Low risk level",
    "risk_level_medium_threshold": "Inclusive lower bound of the Medium risk level",
    "risk_level_high_threshold": "Inclusive lower bound of the High risk level",
    "risk_level_critical_threshold": "Inclusive lower bound of the Critical risk level",
}
_OLD_DESCRIPTIONS = {
    "risk_level_medium_threshold": "Inclusive lower bound of the Medium risk level",
    "risk_level_high_threshold": "Inclusive lower bound of the High risk level",
    "risk_level_very_high_threshold": "Inclusive lower bound of the Very High risk level",
    "risk_level_critical_threshold": "Inclusive lower bound of the Critical risk level",
}


def _upsert(bind, key: str, value, description: str) -> None:
    updated = bind.execute(
        sa.text(
            "UPDATE risk_settings SET setting_value = :value, "
            "description = :description WHERE setting_key = :key"
        ),
        {"key": key, "value": str(int(float(value))), "description": description},
    ).rowcount
    if not updated:
        # is_editable/created_at/updated_at are NOT NULL with no server default,
        # so an insert has to supply them explicitly.
        bind.execute(
            sa.text(
                "INSERT INTO risk_settings "
                "(setting_key, setting_value, value_type, description, "
                " is_editable, created_at, updated_at) "
                "VALUES (:key, :value, 'int', :description, true, :now, :now)"
            ),
            {"key": key, "value": str(int(float(value))),
             "description": description, "now": datetime.utcnow()},
        )


def _rederive_levels(bind, bands, floor: str) -> None:
    """Rewrite every stored risk_level from its score under `bands`.

    Highest band first, so a score exactly on a boundary lands in the higher
    band -- the same tie-break risk_level_for_score() uses. A NULL score keeps
    whatever level it has: there is nothing to derive one from. `floor` is the
    level below the lowest configured bound (informational for the new
    scheme, low for the old one).
    """
    case = "CASE WHEN {col} IS NULL THEN risk_level"
    for level, _key, bound in reversed(bands):
        case += f" WHEN {{col}} >= {float(bound):g} THEN '{level}'"
    case += f" ELSE '{floor}' END"

    for table, col in (("asset_risk_scores", "final_risk_score"),
                       ("asset_risk_history", "risk_score")):
        bind.execute(sa.text(
            f"UPDATE {table} SET risk_level = " + case.format(col=col)
        ))


def upgrade() -> None:
    bind = op.get_bind()

    for level, key, default in _NEW_BANDS:
        _upsert(bind, key, default, _NEW_DESCRIPTIONS[key])
    bind.execute(
        sa.text("DELETE FROM risk_settings WHERE setting_key = :key"),
        {"key": _RETIRED_KEY},
    )
    bind.execute(
        sa.text("DELETE FROM risk_settings WHERE setting_key = :key"),
        {"key": _RETIRED_AR_KEY},
    )

    _rederive_levels(bind, _NEW_BANDS, floor="informational")


def downgrade() -> None:
    bind = op.get_bind()

    for level, key, default in _OLD_BANDS:
        _upsert(bind, key, default, _OLD_DESCRIPTIONS[key])
    bind.execute(
        sa.text("DELETE FROM risk_settings WHERE setting_key = :key"),
        {"key": "risk_level_low_threshold"},
    )
    now = datetime.utcnow()
    bind.execute(
        sa.text(
            "INSERT INTO risk_settings "
            "(setting_key, setting_value, value_type, description, "
            " is_editable, created_at, updated_at) "
            "VALUES (:key, '90', 'int', :description, true, :now, :now)"
        ),
        {"key": _RETIRED_AR_KEY,
         "description": "AR score for assets with the legacy risk level very_high",
         "now": now},
    )

    _rederive_levels(bind, _OLD_BANDS, floor="low")
