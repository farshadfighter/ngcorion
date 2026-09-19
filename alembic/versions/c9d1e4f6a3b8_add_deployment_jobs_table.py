"""add deployment_jobs table

Revision ID: c9d1e4f6a3b8
Revises: b7f3d5a9c2e1
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c9d1e4f6a3b8'
down_revision: Union[str, Sequence[str], None] = 'b7f3d5a9c2e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'deployment_jobs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('configuration_object_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('asset_name', sa.String(length=200), nullable=True),
        sa.Column('device_type', sa.String(length=30), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='queued'),
        sa.Column('precheck_output', sa.Text(), nullable=True),
        sa.Column('backup_id', sa.Integer(), nullable=True),
        sa.Column('apply_output', sa.Text(), nullable=True),
        sa.Column('verify_output', sa.Text(), nullable=True),
        sa.Column('rollback_output', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['configuration_object_id'], ['configuration_objects.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['backup_id'], ['device_backups.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_deployment_jobs_id'), 'deployment_jobs', ['id'], unique=False)
    op.create_index(op.f('ix_deployment_jobs_configuration_object_id'), 'deployment_jobs', ['configuration_object_id'], unique=False)
    op.create_index(op.f('ix_deployment_jobs_asset_id'), 'deployment_jobs', ['asset_id'], unique=False)
    op.create_index(op.f('ix_deployment_jobs_status'), 'deployment_jobs', ['status'], unique=False)
    op.create_index(op.f('ix_deployment_jobs_created_at'), 'deployment_jobs', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_deployment_jobs_created_at'), table_name='deployment_jobs')
    op.drop_index(op.f('ix_deployment_jobs_status'), table_name='deployment_jobs')
    op.drop_index(op.f('ix_deployment_jobs_asset_id'), table_name='deployment_jobs')
    op.drop_index(op.f('ix_deployment_jobs_configuration_object_id'), table_name='deployment_jobs')
    op.drop_index(op.f('ix_deployment_jobs_id'), table_name='deployment_jobs')
    op.drop_table('deployment_jobs')
