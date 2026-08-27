"""Normalise the risk-level threshold keys and re-derive every stored level.

The same score could read as two different levels because two conventions for
the same ``risk_settings`` keys were live at once:

* the *offset* convention the calculation service read, where
  ``risk_level_<name>_threshold`` was the lower bound of the band **above**
  ``<name>`` (``risk_level_high_threshold`` = 60 opened Very High) and there was
  no ``*_very_high_threshold`` key;
* the *natural* convention seeded by d4f6a8b0c2e1, where each key is the lower
  bound of the band it names (medium=20, high=40, very_high=60, critical=80).

A database carrying the natural rows had them read as if they were offset ones,
so a score of 50 came out ``very_high`` from the live settings but ``high`` from
the code defaults and from the a4c7e1b90d52 backfill. Whichever ran last for a
given asset is the level that stuck, and rows written on either side of that
disagreed for identical scores.

app/modules/risk/levels.py now settles this on the natural convention and is the
only implementation of the rule. This revision brings the stored rows to match:

1. rewrite ``risk_settings`` into the natural convention, whichever one it holds
   (an offset table is shifted down one band; ``risk_level_low_threshold`` is
   dropped because ``low`` is the floor and has no configurable lower bound);
2. re-derive ``risk_level`` in ``asset_risk_scores`` and ``asset_risk_history``
   from the stored score under those normalised bounds, so no row keeps a level
   the current rule would not produce.

Step 2 repeats what a4c7e1b90d52 did, deliberately: that revision hardcoded the
bands and could not see the settings rows that were contradicting them.

Revision ID: c3a91f57d8b4
Revises: a4c7e1b90d52
"""
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c3a91f57d8b4'
down_revision: Union[str, Sequence[str], None] = 'a4c7e1b90d52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Band -> (setting key, default lower bound). Mirrors
# app/modules/risk/levels.py::LEVEL_THRESHOLD_KEYS; restated here because a
# migration must keep working against the schema of its own moment, not
# whatever the application code says later.
_BANDS = (
    ("medium", "risk_level_medium_threshold", 20),
    ("high", "risk_level_high_threshold", 40),
    ("very_high", "risk_level_very_high_threshold", 60),
    ("critical", "risk_level_critical_threshold", 80),
)

_RETIRED_KEY = "risk_level_low_threshold"

# The offset convention's keys, in the order their values map onto the natural
# ones: old low -> medium, old medium -> high, old high -> very_high,
# old critical -> critical.
_OFFSET_SOURCE_KEYS = (
    _RETIRED_KEY,
    "risk_level_medium_threshold",
    "risk_level_high_threshold",
    "risk_level_critical_threshold",
)

_DESCRIPTIONS = {
    "risk_level_medium_threshold": "Inclusive lower bound of the Medium risk level",
    "risk_level_high_threshold": "Inclusive lower bound of the High risk level",
    "risk_level_very_high_threshold": "Inclusive lower bound of the Very High risk level",
    "risk_level_critical_threshold": "Inclusive lower bound of the Critical risk level",
}


def _stored(bind) -> dict:
    rows = bind.execute(sa.text(
        "SELECT setting_key, setting_value FROM risk_settings "
        "WHERE setting_key LIKE 'risk_level_%_threshold'"
    )).fetchall()
    return {key: value for key, value in rows}


def _upsert(bind, key: str, value) -> None:
    updated = bind.execute(
        sa.text(
            "UPDATE risk_settings SET setting_value = :value, "
            "description = :description WHERE setting_key = :key"
        ),
        {"key": key, "value": str(int(float(value))),
         "description": _DESCRIPTIONS[key]},
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
             "description": _DESCRIPTIONS[key], "now": datetime.utcnow()},
        )


def _rederive_levels(bind, bounds: dict) -> None:
    """Rewrite every stored risk_level from its score under `bounds`.

    Highest band first, so a score exactly on a boundary lands in the higher
    band — the same tie-break risk_level_for_score() uses. A NULL score keeps
    whatever level it has: there is nothing to derive one from.
    """
    case = "CASE WHEN {col} IS NULL THEN risk_level"
    for level, key, _default in reversed(_BANDS):
        case += f" WHEN {{col}} >= {float(bounds[key]):g} THEN '{level}'"
    case += " ELSE 'low' END"

    for table, col in (("asset_risk_scores", "final_risk_score"),
                       ("asset_risk_history", "risk_score")):
        bind.execute(sa.text(
            f"UPDATE {table} SET risk_level = " + case.format(col=col)
        ))


def upgrade() -> None:
    bind = op.get_bind()
    stored = _stored(bind)

    if _RETIRED_KEY in stored:
        # Offset convention: each stored value is the lower bound of the band
        # one step up from the key that holds it, so shifting the values down
        # one key preserves the operator's actual band edges.
        values = [stored.get(key) for key in _OFFSET_SOURCE_KEYS]
        bounds = {
            key: (values[index] if values[index] is not None else default)
            for index, (_level, key, default) in enumerate(_BANDS)
        }
    else:
        # Natural convention (or nothing stored yet): keep what is there.
        bounds = {
            key: stored.get(key, default) for _level, key, default in _BANDS
        }

    # A table that was mid-migration could hold a non-ascending mix; fall back
    # to the defaults rather than writing bands that overlap.
    ordered = [float(bounds[key]) for _l, key, _d in _BANDS]
    if any(a >= b for a, b in zip(ordered, ordered[1:])) or ordered[0] < 0 or ordered[-1] > 100:
        bounds = {key: default for _level, key, default in _BANDS}

    for _level, key, _default in _BANDS:
        _upsert(bind, key, bounds[key])
    bind.execute(
        sa.text("DELETE FROM risk_settings WHERE setting_key = :key"),
        {"key": _RETIRED_KEY},
    )

    _rederive_levels(bind, bounds)


def downgrade() -> None:
    """Restore the offset convention's keys and values.

    The stored levels are left as this revision derived them: they are correct
    under both conventions once the values are shifted back, and re-deriving
    them again would only reintroduce the drift.
    """
    bind = op.get_bind()
    stored = _stored(bind)
    bounds = {key: stored.get(key, default) for _level, key, default in _BANDS}

    now = datetime.utcnow()
    bind.execute(
        sa.text(
            "INSERT INTO risk_settings "
            "(setting_key, setting_value, value_type, description, "
            " is_editable, created_at, updated_at) "
            "VALUES (:key, :value, 'int', :description, true, :now, :now)"
        ),
        {"key": _RETIRED_KEY, "value": str(int(float(bounds["risk_level_medium_threshold"]))),
         "description": "Lower bound of the Low risk level", "now": now},
    )
    for target, source in (
        ("risk_level_medium_threshold", "risk_level_high_threshold"),
        ("risk_level_high_threshold", "risk_level_very_high_threshold"),
    ):
        bind.execute(
            sa.text("UPDATE risk_settings SET setting_value = :value "
                    "WHERE setting_key = :key"),
            {"key": target, "value": str(int(float(bounds[source])))},
        )
    bind.execute(
        sa.text("DELETE FROM risk_settings "
                "WHERE setting_key = 'risk_level_very_high_threshold'")
    )
