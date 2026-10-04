"""Forced password change: users.must_change_password

Revision ID: f9c2d4e6a8b0
Revises: e8b1c3d5f7a2
Create Date: 2026-10-04 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'f9c2d4e6a8b0'
down_revision: Union[str, Sequence[str], None] = 'e8b1c3d5f7a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing accounts keep working as they are (false).
    op.add_column("users", sa.Column("must_change_password", sa.Boolean(), nullable=False,
                                     server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
