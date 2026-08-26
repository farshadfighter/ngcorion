"""Re-derive stored risk levels from stored scores under the spec's bands.

Revision e5c1a7d93b48 rewrote every stored risk_level into its own five-band
scheme (informational/low/medium/high/critical). The next revision,
f9d2b6e41a73, restored the spec's bands in risk_settings and the calculation
service went back to emitting low/medium/high/very_high/critical -- but it only
updated the settings rows, never the levels already stored.

The result is that any asset not recalculated since then still carries a label
from the old scheme, so risk_score and risk_level disagree: a score of 50 reads
"medium" under the old bands but is "high" under the spec's. 'informational' is
also still present even though the engine can no longer produce it.

This re-derives risk_level from the score everywhere it is stored, using the
same inclusive lower bounds as service.py::_risk_level (20/40/60/80), so the
two columns agree without waiting for a recalculation of every asset.

Runs after b3f7c1d9e2a4 (the PDF six-factor restore), which re-derives the
stored levels into the PDF's informational/low/medium/high/critical bands. The
client requires the very_high scheme instead, so this revision re-derives them
once more and is the last word on the level text. The weight/zone changes from
b3f7c1d9e2a4 are left untouched -- only the level bands differ.

Revision ID: a4c7e1b90d52
Revises: b3f7c1d9e2a4
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a4c7e1b90d52'
down_revision: Union[str, Sequence[str], None] = 'b3f7c1d9e2a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Inclusive lower bounds, highest band first -- mirrors _risk_level() exactly:
#   <20 low | 20-40 medium | 40-60 high | 60-80 very_high | >=80 critical
_SPEC_LEVEL_CASE = """
    CASE
        WHEN {col} IS NULL THEN risk_level
        WHEN {col} >= 80 THEN 'critical'
        WHEN {col} >= 60 THEN 'very_high'
        WHEN {col} >= 40 THEN 'high'
        WHEN {col} >= 20 THEN 'medium'
        ELSE 'low'
    END
"""

# The bands e5c1a7d93b48 left behind, for downgrade().
_PREV_LEVEL_CASE = """
    CASE
        WHEN {col} IS NULL THEN risk_level
        WHEN {col} > 80 THEN 'critical'
        WHEN {col} > 60 THEN 'high'
        WHEN {col} > 40 THEN 'medium'
        WHEN {col} > 20 THEN 'low'
        ELSE 'informational'
    END
"""


def _rewrite(case: str) -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        "UPDATE asset_risk_scores SET risk_level = "
        + case.format(col="final_risk_score")
    ))
    bind.execute(sa.text(
        "UPDATE asset_risk_history SET risk_level = "
        + case.format(col="risk_score")
    ))


def upgrade() -> None:
    _rewrite(_SPEC_LEVEL_CASE)


def downgrade() -> None:
    _rewrite(_PREV_LEVEL_CASE)
