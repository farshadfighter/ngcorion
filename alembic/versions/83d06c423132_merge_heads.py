"""merge heads

Revision ID: 83d06c423132
Revises: 20260524_add_unit, 67d30cf5e0b9
Create Date: 2026-05-26 12:16:54.111952

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '83d06c423132'
down_revision: Union[str, Sequence[str], None] = ('20260524_add_unit', '67d30cf5e0b9')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
