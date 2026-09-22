"""merge asset-hosting with scheduling/cve/noc heads

Revision ID: 550120c4c577
Revises: 067dee66c5e2, 1fa08af4f364
Create Date: 2026-09-22 05:52:48.391015

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '550120c4c577'
down_revision: Union[str, Sequence[str], None] = ('067dee66c5e2', '1fa08af4f364')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
