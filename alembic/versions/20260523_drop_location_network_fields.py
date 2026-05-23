"""drop network_zone vlan_id subnet from asset_locations

Revision ID: 20260523_drop_loc_net
Revises: 8ac52e9c6d6a
Create Date: 2026-05-23

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '20260523_drop_loc_net'
down_revision: Union[str, Sequence[str], None] = '8ac52e9c6d6a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index('ix_asset_locations_network_zone', table_name='asset_locations', if_exists=True)
    op.drop_column('asset_locations', 'network_zone')
    op.drop_column('asset_locations', 'vlan_id')
    op.drop_column('asset_locations', 'subnet')


def downgrade() -> None:
    op.add_column('asset_locations', sa.Column('subnet', sa.String(50), nullable=True))
    op.add_column('asset_locations', sa.Column('vlan_id', sa.Integer(), nullable=True))
    op.add_column('asset_locations', sa.Column('network_zone', sa.String(100), nullable=True))
    op.create_index('ix_asset_locations_network_zone', 'asset_locations', ['network_zone'])
