"""add RISK value to moduleenum for risk module permissions

Revision ID: a4c2d91e7b30
Revises: 931114c3a14b
Create Date: 2026-07-27

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a4c2d91e7b30'
down_revision: Union[str, Sequence[str], None] = '931114c3a14b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'RISK'")


def downgrade() -> None:
    """Downgrade schema."""
    # PostgreSQL cannot remove a value from an enum type; leaving 'RISK'
    # in place is harmless once user_permissions rows referencing it are gone.
    pass
