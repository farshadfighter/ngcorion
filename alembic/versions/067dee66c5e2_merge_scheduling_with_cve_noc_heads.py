"""merge scheduling with cve/noc heads

Revision ID: 067dee66c5e2
Revises: a3813ed6a25d, ece2eb5619ba
Create Date: 2026-09-22 05:51:14.353358

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '067dee66c5e2'
down_revision: Union[str, Sequence[str], None] = ('a3813ed6a25d', 'ece2eb5619ba')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
