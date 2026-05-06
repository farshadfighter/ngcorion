"""merge heads

Revision ID: e02d17baefa3
Revises: 7c8c6fdd501f, f9a3c7e8d2b1
Create Date: 2026-05-06 04:59:24.286930

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e02d17baefa3'
down_revision: Union[str, Sequence[str], None] = ('7c8c6fdd501f', 'f9a3c7e8d2b1')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
