"""Sophos Firewall audits: devicetype enum value

Revision ID: d7a0f2b4c9e1
Revises: c6f9e1a3b8d0
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'd7a0f2b4c9e1'
down_revision: Union[str, Sequence[str], None] = 'c6f9e1a3b8d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'SOPHOS'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
