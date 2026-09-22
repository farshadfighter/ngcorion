"""add NOC value to moduleenum for the NOC monitoring module

Revision ID: c8ed1dfbbf0d
Revises: 3451824a39b2
Create Date: 2026-09-20 08:20:00.000000

Mirrors c1e9a4f7b2d6 / 2184b555dc50 (which added the other module values):
without a matching moduleenum value, require_permission("noc", ...) can
never match a granted permission and every non-admin user is denied.

The enum value is added in an autocommit block: PostgreSQL forbids using a
new enum value in the same transaction that added it, and older servers
forbid ALTER TYPE ... ADD VALUE inside a transaction entirely.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c8ed1dfbbf0d'
down_revision: Union[str, Sequence[str], None] = '3451824a39b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'NOC'")


def downgrade() -> None:
    """PostgreSQL cannot drop a value from an enum type - see c1e9a4f7b2d6's
    downgrade for the full rationale. No-op; roll back in practice by
    deleting user_permissions rows where module = 'NOC'."""
    pass
