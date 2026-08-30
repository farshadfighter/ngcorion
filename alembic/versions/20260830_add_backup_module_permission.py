"""add BACKUP value to moduleenum for configuration-backup permissions

Revision ID: b8d4e2f1a970
Revises: e8f2a1c9b6d3
Create Date: 2026-08-30

Configuration Backup had no module of its own. The page was guarded by
RequirePermission module="backup", a value ModuleEnum never defined, so the
permission lookup could not match and every non-admin was denied — while the
API behind it checked require_permission("hardening", ...), meaning the page
and its endpoints disagreed about who was allowed in.

This adds BACKUP so the module can be granted per user in User Management,
exactly as RISK was added in a4c2d91e7b30 and SYSTEM_CONFIG in c7e1b93a5d02.
The backup router moves onto it in the same change.

Existing installs need no data backfill: admins bypass the permission check in
code, and no row referenced 'backup' before (the value did not exist).

The enum value is added in an autocommit block: PostgreSQL forbids using a new
enum value in the same transaction that added it, and older servers forbid
ALTER TYPE ... ADD VALUE inside a transaction entirely.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'b8d4e2f1a970'
down_revision: Union[str, Sequence[str], None] = 'e8f2a1c9b6d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add 'BACKUP' to the moduleenum PostgreSQL type."""
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'BACKUP'")


def downgrade() -> None:
    """
    PostgreSQL cannot drop a value from an enum type; removing it would mean
    recreating moduleenum and rewriting every column that uses it. Left as a
    no-op for safety, matching a4c2d91e7b30 and c7e1b93a5d02.

    To roll back in practice, delete the user_permissions rows whose module is
    'BACKUP' — the unused enum value is harmless on its own.
    """
    pass
