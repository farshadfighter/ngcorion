"""add_mongodb_to_devicetype_enum

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-19 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add 'mongodb' value to the devicetype PostgreSQL enum."""
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction in PostgreSQL
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'mongodb'")


def downgrade() -> None:
    """
    PostgreSQL does not support removing enum values directly.
    A full enum recreation would be required; left as no-op for safety.
    """
    pass
