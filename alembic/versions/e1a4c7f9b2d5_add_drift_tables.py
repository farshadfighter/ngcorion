"""add drift_runs and drift_results tables

Revision ID: e1a4c7f9b2d5
Revises: c9d1e4f6a3b8
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1a4c7f9b2d5'
down_revision: Union[str, Sequence[str], None] = 'c9d1e4f6a3b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'drift_runs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('triggered_by', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='running'),
        sa.Column('assets_checked', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('drift_found_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['triggered_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_drift_runs_id'), 'drift_runs', ['id'], unique=False)
    op.create_index(op.f('ix_drift_runs_asset_id'), 'drift_runs', ['asset_id'], unique=False)
    op.create_index(op.f('ix_drift_runs_started_at'), 'drift_runs', ['started_at'], unique=False)

    op.create_table(
        'drift_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('run_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('asset_name', sa.String(length=200), nullable=True),
        sa.Column('technology', sa.String(length=30), nullable=True),
        sa.Column('baseline_backup_id', sa.Integer(), nullable=True),
        sa.Column('diff', sa.Text(), nullable=False),
        sa.Column('lines_changed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='low'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='open'),
        sa.Column('ignored_reason', sa.Text(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['run_id'], ['drift_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['baseline_backup_id'], ['device_backups.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_drift_results_id'), 'drift_results', ['id'], unique=False)
    op.create_index(op.f('ix_drift_results_run_id'), 'drift_results', ['run_id'], unique=False)
    op.create_index(op.f('ix_drift_results_asset_id'), 'drift_results', ['asset_id'], unique=False)
    op.create_index(op.f('ix_drift_results_status'), 'drift_results', ['status'], unique=False)
    op.create_index(op.f('ix_drift_results_created_at'), 'drift_results', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_drift_results_created_at'), table_name='drift_results')
    op.drop_index(op.f('ix_drift_results_status'), table_name='drift_results')
    op.drop_index(op.f('ix_drift_results_asset_id'), table_name='drift_results')
    op.drop_index(op.f('ix_drift_results_run_id'), table_name='drift_results')
    op.drop_index(op.f('ix_drift_results_id'), table_name='drift_results')
    op.drop_table('drift_results')

    op.drop_index(op.f('ix_drift_runs_started_at'), table_name='drift_runs')
    op.drop_index(op.f('ix_drift_runs_asset_id'), table_name='drift_runs')
    op.drop_index(op.f('ix_drift_runs_id'), table_name='drift_runs')
    op.drop_table('drift_runs')
