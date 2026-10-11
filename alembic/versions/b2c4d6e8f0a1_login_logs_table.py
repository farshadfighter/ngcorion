"""login_logs: created by a migration, not only by create_all

Revision ID: b2c4d6e8f0a1
Revises: a1d3f5b7c9e2
Create Date: 2026-10-11

The sign-in history table was only ever made by Base.metadata.create_all when the application
started; no migration created it. A database built from the migrations alone (CI, a restore into
an empty database, any tool that runs Alembic before the app) had no login_logs, so the login
rate limiter and the audit trail failed until the app had started once. Every other table comes
from a migration; this one now does too.

Existing installations already have the table (create_all made it at their first start): it is
left as it is. Downgrading does not drop it, for the same reason: it holds the sign-in history.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b2c4d6e8f0a1"
down_revision: Union[str, Sequence[str], None] = "a1d3f5b7c9e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("login_logs"):
        return
    op.create_table(
        "login_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("message", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_login_logs_id", "login_logs", ["id"])
    op.create_index("ix_login_logs_username", "login_logs", ["username"])


def downgrade() -> None:
    # Not dropped: on most installations the table predates this migration and holds the
    # sign-in history (see the module docstring).
    pass
