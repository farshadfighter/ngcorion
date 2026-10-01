"""user interface language

Revision ID: e349a4df1521
Revises: 1a6a137afc58
Create Date: 2026-10-01 18:05:00.077246

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e349a4df1521'
down_revision: Union[str, Sequence[str], None] = '1a6a137afc58'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("language", sa.String(5), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "language")
