"""Align risk scoring with the spec's four-component formula.

The previous revision (e5c1a7d93b48) spread the score over six weighted
components. The Risk & Exposure Intelligence spec defines four:

    Risk Score = 0.25*Criticality + 0.20*Zone + 0.15*OpenPort + 0.40*Audit

AR (the asset's own risk level) and HF (hardening fixes found) stay in the
tables and the breakdown, but drop to weight 0: hardening is meant to lower
risk by resolving findings out of AF (spec section 9), not by adding a term
of its own.

Also corrects three values that drifted from the spec:
  * severity_medium_weight  4 -> 3   (section 8.1)
  * open_port_normalization_factor  1 -> 4   (section 7.4)
  * risk level thresholds to 20/40/60/80 as inclusive lower bounds
    (section 10 — 20 is Medium, 80 is Critical)

Revision ID: f9d2b6e41a73
Revises: e5c1a7d93b48
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'f9d2b6e41a73'
down_revision: Union[str, Sequence[str], None] = 'e5c1a7d93b48'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (setting_key, spec value, previous value used by e5c1a7d93b48)
SPEC_VALUES = [
    ("criticality_weight", "25", "20"),
    ("zone_weight", "20", "15"),
    ("open_port_weight", "15", "10"),
    ("audit_weight", "40", "25"),
    ("asset_risk_weight", "0", "20"),
    ("hardening_weight", "0", "10"),
    ("severity_medium_weight", "3", "4"),
    ("open_port_normalization_factor", "4", "1"),
    ("risk_level_low_threshold", "20", "20"),
    ("risk_level_medium_threshold", "40", "40"),
    ("risk_level_high_threshold", "60", "60"),
    ("risk_level_critical_threshold", "80", "80"),
]


def _apply(pairs):
    connection = op.get_bind()
    for key, value in pairs:
        connection.execute(
            sa.text(
                "UPDATE risk_settings SET setting_value = :value, "
                "updated_at = NOW() WHERE setting_key = :key"
            ),
            {"key": key, "value": value},
        )


def upgrade() -> None:
    _apply([(key, value) for key, value, _ in SPEC_VALUES])


def downgrade() -> None:
    _apply([(key, previous) for key, _, previous in SPEC_VALUES])
