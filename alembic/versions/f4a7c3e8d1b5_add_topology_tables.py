"""add topology_links and topology_logs tables

Revision ID: f4a7c3e8d1b5
Revises: c1e9a4f7b2d6
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4a7c3e8d1b5'
down_revision: Union[str, Sequence[str], None] = 'c1e9a4f7b2d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'topology_links',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('source_asset_id', sa.Integer(), nullable=False),
        sa.Column('destination_asset_id', sa.Integer(), nullable=False),
        sa.Column('source_interface', sa.String(length=50), nullable=True),
        sa.Column('destination_interface', sa.String(length=50), nullable=True),
        sa.Column('link_type', sa.String(length=30), nullable=False, server_default='ethernet'),
        sa.Column('speed_mbps', sa.Integer(), nullable=True),
        sa.Column('vlan', sa.String(length=20), nullable=True),
        sa.Column('subnet', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active'),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['source_asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['destination_asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_topology_links_id'), 'topology_links', ['id'], unique=False)
    op.create_index(op.f('ix_topology_links_source_asset_id'), 'topology_links', ['source_asset_id'], unique=False)
    op.create_index(op.f('ix_topology_links_destination_asset_id'), 'topology_links', ['destination_asset_id'], unique=False)
    op.create_index(op.f('ix_topology_links_created_at'), 'topology_links', ['created_at'], unique=False)

    op.create_table(
        'topology_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True, comment='User who performed the action'),
        sa.Column('action', sa.String(length=64), nullable=False, comment='Action type: create, update, delete'),
        sa.Column('link_id', sa.Integer(), nullable=True, comment='ID of the affected topology link'),
        sa.Column('details', sa.JSON(), nullable=True, comment='Additional context (endpoints, field changes, etc.)'),
        sa.Column('status', sa.String(length=32), nullable=True, server_default='success'),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_topology_logs_id'), 'topology_logs', ['id'], unique=False)
    op.create_index(op.f('ix_topology_logs_user_id'), 'topology_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_topology_logs_action'), 'topology_logs', ['action'], unique=False)
    op.create_index(op.f('ix_topology_logs_link_id'), 'topology_logs', ['link_id'], unique=False)
    op.create_index(op.f('ix_topology_logs_timestamp'), 'topology_logs', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_topology_logs_timestamp'), table_name='topology_logs')
    op.drop_index(op.f('ix_topology_logs_link_id'), table_name='topology_logs')
    op.drop_index(op.f('ix_topology_logs_action'), table_name='topology_logs')
    op.drop_index(op.f('ix_topology_logs_user_id'), table_name='topology_logs')
    op.drop_index(op.f('ix_topology_logs_id'), table_name='topology_logs')
    op.drop_table('topology_logs')

    op.drop_index(op.f('ix_topology_links_created_at'), table_name='topology_links')
    op.drop_index(op.f('ix_topology_links_destination_asset_id'), table_name='topology_links')
    op.drop_index(op.f('ix_topology_links_source_asset_id'), table_name='topology_links')
    op.drop_index(op.f('ix_topology_links_id'), table_name='topology_links')
    op.drop_table('topology_links')
