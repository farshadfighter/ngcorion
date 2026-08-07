"""add very_high to risklevelenum

Revision ID: f1a2b3c4d5e6
Revises: a4c2d91e7b30
Create Date: 2026-08-07 00:00:00.000000

Adds the VERY_HIGH member to the ``risklevelenum`` PostgreSQL enum used by
``asset_inventory.risk_level``.

Note on the value: SQLAlchemy's ``Enum(RiskLevelEnum)`` persists the enum
*member name* (the type was created with values 'LOW','MEDIUM','HIGH',
'CRITICAL'), so the value added here is the member name 'VERY_HIGH', not the
lowercase ``.value`` "very_high". It is inserted BEFORE 'CRITICAL' to keep the
enum's sort order aligned with the Python enum (LOW < ... < VERY_HIGH < CRITICAL).
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = 'a4c2d91e7b30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add 'VERY_HIGH' value to the risklevelenum PostgreSQL enum."""
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction in PostgreSQL
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TYPE risklevelenum ADD VALUE IF NOT EXISTS 'VERY_HIGH' BEFORE 'CRITICAL'"
        )


def downgrade() -> None:
    """
    PostgreSQL does not support removing enum values directly.
    A full enum recreation would be required; left as no-op for safety.
    """
    pass
