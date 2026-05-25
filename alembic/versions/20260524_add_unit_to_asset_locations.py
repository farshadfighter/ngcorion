"""add unit to asset_locations

Revision ID: 20260524_add_unit
Revises: 20260523_drop_loc_net
Create Date: 2026-05-24

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '20260524_add_unit'
down_revision: Union[str, Sequence[str], None] = '20260523_drop_loc_net'
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
