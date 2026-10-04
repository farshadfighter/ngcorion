"""Kubernetes audits: devicetype enum value

Revision ID: f3c6b8d0e5a7
Revises: e2b5a7c9d4f6
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'f3c6b8d0e5a7'
down_revision: Union[str, Sequence[str], None] = 'e2b5a7c9d4f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'KUBERNETES'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value (see a7d1c3e5b9f2).
    pass
