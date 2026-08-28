"""
The single authoritative score -> risk level rule.

Why this module exists
----------------------
``risk_level`` is stored denormalised next to ``final_risk_score`` in
``asset_risk_scores`` (and ``asset_risk_history``). Nothing recomputes it when
the bands move, so any disagreement about where a band starts is frozen into
the rows written while that disagreement was live — and the same score then
reads as two different levels depending on when its row was last calculated.

That is exactly what happened. Two conventions for the same setting keys were
in use at once:

* the *offset* convention, where ``risk_level_<name>_threshold`` was the lower
  bound of the band **above** ``<name>`` (so ``risk_level_high_threshold`` = 60
  opened Very High) and there was no ``*_very_high_threshold`` key at all;
* the *natural* convention seeded by 20260813_add_missing_risk_settings, where
  each key is the lower bound of the band it names (medium=20, high=40,
  very_high=60, critical=80).

``service.py`` read the keys the first way while the rows in ``risk_settings``
held the second, so a score of 50 came out "very_high" from the live settings,
"high" from the code defaults, and "high" again from the a4c7e1b90d52 data
migration. Three answers, one score.

This module settles it on the natural convention — every key is the inclusive
lower bound of the band it names — and is the only place the mapping is
written. The calculation service, the settings validation and the data
migration all go through it.

Bands (spec section 10, and the five-level client requirement that keeps
``very_high`` rather than the PDF's ``informational``)::

    0 <= s < 20   low
    20 <= s < 40  medium
    40 <= s < 60  high
    60 <= s < 80  very_high
    80 <= s <= 100 critical

A score on a boundary belongs to the higher band.
"""
from typing import Dict, Mapping, Sequence

# Lowest band first. ``low`` is the floor and has no configurable lower bound,
# which is why there is no ``risk_level_low_threshold``: a key for it can only
# ever be redundant with 0, and its former existence is what made the offset
# convention look plausible.
RISK_LEVELS: Sequence[str] = ("low", "medium", "high", "very_high", "critical")

# Band name -> the risk_settings key holding its inclusive lower bound,
# ordered lowest to highest.
LEVEL_THRESHOLD_KEYS: Sequence[tuple] = (
    ("medium", "risk_level_medium_threshold"),
    ("high", "risk_level_high_threshold"),
    ("very_high", "risk_level_very_high_threshold"),
    ("critical", "risk_level_critical_threshold"),
)

THRESHOLD_KEYS: Sequence[str] = tuple(key for _, key in LEVEL_THRESHOLD_KEYS)

DEFAULT_THRESHOLDS: Dict[str, float] = {
    "risk_level_medium_threshold": 20.0,
    "risk_level_high_threshold": 40.0,
    "risk_level_very_high_threshold": 60.0,
    "risk_level_critical_threshold": 80.0,
}

# Dropped by this change; the migration removes the row. Named here so the
# settings API can reject a write to it with an explanation rather than a
# bare "unknown setting".
RETIRED_THRESHOLD_KEYS: Sequence[str] = ("risk_level_low_threshold",)


def thresholds_from_settings(settings: Mapping) -> Dict[str, float]:
    """Pull the four band bounds out of a settings mapping.

    A missing key falls back to its default. That fallback is deliberately
    *per-key* rather than all-or-nothing so a partially seeded ``risk_settings``
    table still produces a coherent, ascending set of bands instead of the
    silent mix of live and default values that produced the original bug.
    """
    return {
        key: float(settings.get(key, DEFAULT_THRESHOLDS[key]))
        for key in THRESHOLD_KEYS
    }


def risk_level_for_score(score: float, thresholds: Mapping = None) -> str:
    """The risk level for a 0-100 score. The only implementation of this rule.

    ``thresholds`` maps each THRESHOLD_KEYS entry to its inclusive lower bound;
    omit it for the defaults. Evaluated highest band first, so a score sitting
    exactly on a boundary belongs to the higher band (20 is medium, 80 is
    critical).
    """
    bounds = DEFAULT_THRESHOLDS if thresholds is None else thresholds
    value = float(score)
    for level, key in reversed(LEVEL_THRESHOLD_KEYS):
        if value >= float(bounds[key]):
            return level
    return "low"
