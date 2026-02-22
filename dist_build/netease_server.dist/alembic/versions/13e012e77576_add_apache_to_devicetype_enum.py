"""add_apache_to_devicetype_enum

Revision ID: 13e012e77576
Revises: 0f9dda3c6110
Create Date: 2026-02-16 19:09:10.049508

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '13e012e77576'
down_revision: Union[str, Sequence[str], None] = '0f9dda3c6110'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction in PostgreSQL
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'APACHE'")


def downgrade() -> None:
    """Downgrade schema."""
    pass
