"""add port_count to asset_inventory

Revision ID: b7c14e29f0a3
Revises: a3f8d2c6e914
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7c14e29f0a3'
down_revision: Union[str, Sequence[str], None] = 'a3f8d2c6e914'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'asset_inventory',
        sa.Column('port_count', sa.Integer(), nullable=True,
                  comment="Number of physical ports this device actually has"),
    )


def downgrade() -> None:
    op.drop_column('asset_inventory', 'port_count')
