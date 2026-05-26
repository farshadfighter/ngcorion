"""add device_backups table

Revision ID: 67d30cf5e0b9
Revises: da72f461c088
Create Date: 2026-05-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '67d30cf5e0b9'
down_revision: Union[str, Sequence[str], None] = 'da72f461c088'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'device_backups',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False, comment='FK to asset_inventory'),
        sa.Column('asset_name', sa.String(length=255), nullable=True),
        sa.Column('device_ip', sa.String(length=50), nullable=True),
        sa.Column('device_type', sa.String(length=30), nullable=True, comment='cisco / fortinet'),
        sa.Column('config_content', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=20), nullable=False, server_default='manual', comment='manual | hardening'),
        sa.Column('hardening_action_id', sa.Integer(), nullable=True, comment='FK to hardening_actions'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='FK to users'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['hardening_action_id'], ['hardening_actions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_device_backups_id'), 'device_backups', ['id'], unique=False)
    op.create_index(op.f('ix_device_backups_asset_id'), 'device_backups', ['asset_id'], unique=False)
    op.create_index(op.f('ix_device_backups_hardening_action_id'), 'device_backups', ['hardening_action_id'], unique=False)
    op.create_index(op.f('ix_device_backups_created_at'), 'device_backups', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_device_backups_created_at'), table_name='device_backups')
    op.drop_index(op.f('ix_device_backups_hardening_action_id'), table_name='device_backups')
    op.drop_index(op.f('ix_device_backups_asset_id'), table_name='device_backups')
    op.drop_index(op.f('ix_device_backups_id'), table_name='device_backups')
    op.drop_table('device_backups')
