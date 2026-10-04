"""ESXi audits: devicetype enum value

Revision ID: b5e8d0f2a7c9
Revises: a4d7c9e1f6b8
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'b5e8d0f2a7c9'
down_revision: Union[str, Sequence[str], None] = 'a4d7c9e1f6b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'ESXI'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
