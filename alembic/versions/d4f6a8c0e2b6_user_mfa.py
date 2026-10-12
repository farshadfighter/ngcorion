"""user_mfa: two-step sign-in (TOTP) per account

Revision ID: d4f6a8c0e2b6
Revises: c3e5f7a9b1d4
Create Date: 2026-10-11
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d4f6a8c0e2b6"
down_revision: Union[str, Sequence[str], None] = "c3e5f7a9b1d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_mfa",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("pending_secret", sa.Text(), nullable=True),
        sa.Column("last_used_step", sa.Integer(), nullable=True),
        sa.Column("recovery_codes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("user_mfa")
