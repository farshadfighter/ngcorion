"""add TOPOLOGY, ARCHITECTURE_VALIDATION, DESIGN_CONFIGURATION, DEPLOYMENT, DRIFT
values to moduleenum for the new network design / change-automation modules

Revision ID: c1e9a4f7b2d6
Revises: b8d4e2f1a970
Create Date: 2026-09-19

Five new modules are being added (Topology, Architecture Validation,
Design & Configuration, Deployment, Configuration Drift), each guarded by
RequirePermission on the frontend and require_permission(module, ...) on the
backend. Without a matching moduleenum value the permission lookup can never
match and every non-admin would be denied, exactly the bug fixed for BACKUP
in b8d4e2f1a970 - so these five are added here up front, before any router
references them.

The enum values are added in an autocommit block: PostgreSQL forbids using a
new enum value in the same transaction that added it, and older servers
forbid ALTER TYPE ... ADD VALUE inside a transaction entirely.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c1e9a4f7b2d6'
down_revision: Union[str, Sequence[str], None] = 'b8d4e2f1a970'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_VALUES = ("TOPOLOGY", "ARCHITECTURE_VALIDATION", "DESIGN_CONFIGURATION", "DEPLOYMENT", "DRIFT")


def upgrade() -> None:
    """Add the five new module values to the moduleenum PostgreSQL type."""
    with op.get_context().autocommit_block():
        for value in NEW_VALUES:
            op.execute(f"ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    """
    PostgreSQL cannot drop a value from an enum type; removing it would mean
    recreating moduleenum and rewriting every column that uses it. Left as a
    no-op for safety, matching a4c2d91e7b30, c7e1b93a5d02, and b8d4e2f1a970.

    To roll back in practice, delete the user_permissions rows whose module is
    one of these five - the unused enum values are harmless on their own.
    """
    pass
