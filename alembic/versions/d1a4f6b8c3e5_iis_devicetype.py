"""IIS audits: devicetype enum value

Revision ID: d1a4f6b8c3e5
Revises: c9f3e5a7b2d4
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'd1a4f6b8c3e5'
down_revision: Union[str, Sequence[str], None] = 'c9f3e5a7b2d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'IIS'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
