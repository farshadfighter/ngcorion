"""add CVE value to moduleenum for the CVE vulnerability module

Revision ID: 2184b555dc50
Revises: a8d5132ede7a
Create Date: 2026-09-20 07:46:34.860895

Mirrors c1e9a4f7b2d6 (which added TOPOLOGY/ARCHITECTURE_VALIDATION/etc.):
without a matching moduleenum value, require_permission("cve", ...) can
never match a granted permission and every non-admin user is denied.

The enum value is added in an autocommit block: PostgreSQL forbids using a
new enum value in the same transaction that added it, and older servers
forbid ALTER TYPE ... ADD VALUE inside a transaction entirely.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '2184b555dc50'
down_revision: Union[str, Sequence[str], None] = 'a8d5132ede7a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'CVE'")


def downgrade() -> None:
    """PostgreSQL cannot drop a value from an enum type - see c1e9a4f7b2d6's
    downgrade for the full rationale. No-op; roll back in practice by
    deleting user_permissions rows where module = 'CVE'."""
    pass
