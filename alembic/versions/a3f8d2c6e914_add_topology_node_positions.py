"""add topology_node_positions table

Revision ID: a3f8d2c6e914
Revises: e1a4c7f9b2d5
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f8d2c6e914'
down_revision: Union[str, Sequence[str], None] = 'e1a4c7f9b2d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'topology_node_positions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('pos_x', sa.Float(), nullable=False),
        sa.Column('pos_y', sa.Float(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id', name='uq_topology_node_positions_asset_id'),
    )
    op.create_index(op.f('ix_topology_node_positions_id'), 'topology_node_positions', ['id'], unique=False)
    op.create_index(op.f('ix_topology_node_positions_asset_id'), 'topology_node_positions', ['asset_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_topology_node_positions_asset_id'), table_name='topology_node_positions')
    op.drop_index(op.f('ix_topology_node_positions_id'), table_name='topology_node_positions')
    op.drop_table('topology_node_positions')
