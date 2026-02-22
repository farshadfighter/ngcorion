"""add ports and protocol columns to discovery_scans

Revision ID: 62b6732be89b
Revises: e4de134c385b
Create Date: 2025-12-09 14:56:22.391127

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '62b6732be89b'
down_revision: Union[str, Sequence[str], None] = 'e4de134c385b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # NOTE: These columns are now created in migration e4de134c385b
    # This migration is kept for compatibility but does nothing
    pass


def downgrade() -> None:
    """Downgrade schema."""
    # NOTE: Columns are managed in migration e4de134c385b
    pass
