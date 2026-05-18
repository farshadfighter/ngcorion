"""merge multiple heads

Revision ID: 8ac52e9c6d6a
Revises: 20260518_audit_tz, da72f461c088
Create Date: 2026-05-18 09:54:24.578095

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8ac52e9c6d6a'
down_revision: Union[str, Sequence[str], None] = ('20260518_audit_tz', 'da72f461c088')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
