"""merge hardening logs with main branch

Revision ID: da72f461c088
Revises: 20260512_034258, e02d17baefa3
Create Date: 2026-05-12 05:13:44.379964

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'da72f461c088'
down_revision: Union[str, Sequence[str], None] = ('20260512_034258', 'e02d17baefa3')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
