"""Windows DNS Server audits: devicetype enum value

Revision ID: b8e2d4f6a1c3
Revises: a7d1c3e5b9f2
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'b8e2d4f6a1c3'
down_revision: Union[str, Sequence[str], None] = 'a7d1c3e5b9f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'DNS_SERVER'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
