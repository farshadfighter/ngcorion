"""merge cve and noc heads

Revision ID: ece2eb5619ba
Revises: 2184b555dc50, a04f1ad92b7b
Create Date: 2026-09-22 05:47:32.052668

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ece2eb5619ba'
down_revision: Union[str, Sequence[str], None] = ('2184b555dc50', 'a04f1ad92b7b')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
