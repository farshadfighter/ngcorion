"""nginx audits: devicetype enum value

Revision ID: c6f9e1a3b8d0
Revises: b5e8d0f2a7c9
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'c6f9e1a3b8d0'
down_revision: Union[str, Sequence[str], None] = 'b5e8d0f2a7c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'NGINX'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
