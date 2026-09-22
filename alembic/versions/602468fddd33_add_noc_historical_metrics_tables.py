"""add noc historical metrics tables

Revision ID: 602468fddd33
Revises: 550120c4c577
Create Date: 2026-09-22 23:16:32.982035

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '602468fddd33'
down_revision: Union[str, Sequence[str], None] = '550120c4c577'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'asset_metric_samples',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('interface_id', sa.Integer(), nullable=True),
        sa.Column('metric_type', sa.String(length=30), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('sampled_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['interface_id'], ['asset_snmp_interfaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_asset_metric_samples_id'), 'asset_metric_samples', ['id'], unique=False)
    op.create_index(op.f('ix_asset_metric_samples_sampled_at'), 'asset_metric_samples', ['sampled_at'], unique=False)
    op.create_index(
        'ix_asset_metric_samples_lookup', 'asset_metric_samples',
        ['asset_id', 'metric_type', 'sampled_at'], unique=False,
    )
    op.create_index(
        'ix_asset_metric_samples_interface_lookup', 'asset_metric_samples',
        ['interface_id', 'metric_type', 'sampled_at'], unique=False,
    )

    op.create_table(
        'asset_metric_rollups',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('interface_id', sa.Integer(), nullable=True),
        sa.Column('metric_type', sa.String(length=30), nullable=False),
        sa.Column('granularity', sa.String(length=4), nullable=False),
        sa.Column('bucket_start', sa.DateTime(), nullable=False),
        sa.Column('avg_value', sa.Float(), nullable=False),
        sa.Column('min_value', sa.Float(), nullable=False),
        sa.Column('max_value', sa.Float(), nullable=False),
        sa.Column('sample_count', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['interface_id'], ['asset_snmp_interfaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_asset_metric_rollups_id'), 'asset_metric_rollups', ['id'], unique=False)
    op.create_index(
        'ix_asset_metric_rollups_lookup', 'asset_metric_rollups',
        ['asset_id', 'metric_type', 'granularity', 'bucket_start'], unique=False,
    )
    op.create_index(
        'ix_asset_metric_rollups_interface_lookup', 'asset_metric_rollups',
        ['interface_id', 'metric_type', 'granularity', 'bucket_start'], unique=False,
    )


def downgrade() -> None:
    op.drop_index('ix_asset_metric_rollups_interface_lookup', table_name='asset_metric_rollups')
    op.drop_index('ix_asset_metric_rollups_lookup', table_name='asset_metric_rollups')
    op.drop_index(op.f('ix_asset_metric_rollups_id'), table_name='asset_metric_rollups')
    op.drop_table('asset_metric_rollups')

    op.drop_index('ix_asset_metric_samples_interface_lookup', table_name='asset_metric_samples')
    op.drop_index('ix_asset_metric_samples_lookup', table_name='asset_metric_samples')
    op.drop_index(op.f('ix_asset_metric_samples_sampled_at'), table_name='asset_metric_samples')
    op.drop_index(op.f('ix_asset_metric_samples_id'), table_name='asset_metric_samples')
    op.drop_table('asset_metric_samples')
