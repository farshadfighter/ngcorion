"""Docker audits: devicetype enum value

Revision ID: e2b5a7c9d4f6
Revises: d1a4f6b8c3e5
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'e2b5a7c9d4f6'
down_revision: Union[str, Sequence[str], None] = 'd1a4f6b8c3e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'DOCKER'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
