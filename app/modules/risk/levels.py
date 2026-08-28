"""
The single authoritative score -> risk level rule.

Why this module exists
----------------------
``risk_level`` is stored denormalised next to ``final_risk_score`` in
``asset_risk_scores`` (and ``asset_risk_history``). Nothing recomputes it when
the bands move, so any disagreement about where a band starts is frozen into
the rows written while that disagreement was live — and the same score then
reads as two different levels depending on when its row was last calculated.

That is exactly what happened, twice:

* Two conventions for the same setting keys were in use at once (the
  *offset* convention the calculation service read vs. the *natural*
  convention the settings table actually held), so a score of 50 came out
  differently depending on which entry point produced the row. Fixed by
  revision c3a91f57d8b4, which settled on the natural convention below.
* Separately, the five-level scheme itself (``low/medium/high/very_high/
  critical``) did not match the NGCorion Risk Score Calculation
  Specification, which defines exactly five *different* bands:
  ``informational/low/medium/high/critical`` with gapped integer bounds
  (0-20 / 21-40 / 41-60 / 61-80 / 81-100). ``very_high`` had no place in the
  spec at all. Fixed by revision <risk_level_spec_alignment>, which is what
  this module now implements.

This module is the only place the score -> level mapping is written. The
calculation service, the settings validation and the data migrations all go
through it.

Bands (spec section 10)::

    0 <= s <= 20   informational
    21 <= s <= 40  low
    41 <= s <= 60  medium
    61 <= s <= 80  high
    81 <= s <= 100 critical

Expressed here as four *inclusive lower bounds* (21/41/61/81) evaluated
highest band first, which is equivalent to the spec's gapped table for every
integer score (the only kind ``final_risk_score`` ever is, since it is
rounded before classification) and needs no separate "upper bound" concept:
a score of 20 is not >= 21, so it falls through to the floor band
(informational); a score of 21 is.
"""
from typing import Dict, Mapping, Sequence

# Lowest band first. ``informational`` is the floor and has no configurable
# lower bound, which is why there is no ``risk_level_informational_threshold``:
# a key for it can only ever be redundant with 0.
RISK_LEVELS: Sequence[str] = ("informational", "low", "medium", "high", "critical")

# Band name -> the risk_settings key holding its inclusive lower bound,
# ordered lowest to highest.
LEVEL_THRESHOLD_KEYS: Sequence[tuple] = (
    ("low", "risk_level_low_threshold"),
    ("medium", "risk_level_medium_threshold"),
    ("high", "risk_level_high_threshold"),
    ("critical", "risk_level_critical_threshold"),
)

THRESHOLD_KEYS: Sequence[str] = tuple(key for _, key in LEVEL_THRESHOLD_KEYS)

# Spec section 10's gapped table (0-20/21-40/41-60/61-80/81-100) expressed as
# inclusive lower bounds of the band each key names.
DEFAULT_THRESHOLDS: Dict[str, float] = {
    "risk_level_low_threshold": 21.0,
    "risk_level_medium_threshold": 41.0,
    "risk_level_high_threshold": 61.0,
    "risk_level_critical_threshold": 81.0,
}

# Retired by the spec-alignment revision: the old five-level scheme's extra
# band between High and Critical has no place in the spec. Named here so the
# settings API can reject a write to it with an explanation rather than a
# bare "unknown setting".
RETIRED_THRESHOLD_KEYS: Sequence[str] = ("risk_level_very_high_threshold",)


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
    exactly on a boundary belongs to the higher band (21 is low, 81 is
    critical) — the spec's own worked examples land on whole numbers, and this
    tie-break reproduces its gapped table exactly for every integer score.
    """
    bounds = DEFAULT_THRESHOLDS if thresholds is None else thresholds
    value = float(score)
    for level, key in reversed(LEVEL_THRESHOLD_KEYS):
        if value >= float(bounds[key]):
            return level
    return "informational"
