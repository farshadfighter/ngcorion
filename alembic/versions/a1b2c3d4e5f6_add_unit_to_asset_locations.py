"""add unit to asset_locations

Revision ID: a1b2c3d4e5f6
Revises: e02d17baefa3
Create Date: 2026-05-23

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'e02d17baefa3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'asset_locations',
        sa.Column('unit', sa.String(length=50), nullable=True,
                  comment='Unit number or label within the floor/room')
    )


def downgrade() -> None:
    op.drop_column('asset_locations', 'unit')
