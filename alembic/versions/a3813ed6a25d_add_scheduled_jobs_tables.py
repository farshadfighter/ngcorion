"""add scheduled_jobs and scheduled_job_runs tables

Revision ID: a3813ed6a25d
Revises: b7c14e29f0a3
Create Date: 2026-09-20 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3813ed6a25d'
down_revision: Union[str, Sequence[str], None] = 'b7c14e29f0a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scheduled_jobs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('job_name', sa.String(length=200), nullable=False),
        sa.Column('job_type', sa.String(length=20), nullable=False),
        sa.Column('technology', sa.String(length=20), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('params_encrypted', sa.Text(), nullable=False),
        sa.Column('recurrence', sa.String(length=20), nullable=False, server_default='daily'),
        sa.Column('hour', sa.Integer(), nullable=True),
        sa.Column('minute', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('day_of_week', sa.Integer(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('next_run_at', sa.DateTime(), nullable=False),
        sa.Column('last_run_at', sa.DateTime(), nullable=True),
        sa.Column('last_run_status', sa.String(length=20), nullable=True),
        sa.Column('last_run_message', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scheduled_jobs_id'), 'scheduled_jobs', ['id'], unique=False)
    op.create_index(op.f('ix_scheduled_jobs_job_type'), 'scheduled_jobs', ['job_type'], unique=False)
    op.create_index(op.f('ix_scheduled_jobs_asset_id'), 'scheduled_jobs', ['asset_id'], unique=False)
    op.create_index(op.f('ix_scheduled_jobs_enabled'), 'scheduled_jobs', ['enabled'], unique=False)
    op.create_index(op.f('ix_scheduled_jobs_next_run_at'), 'scheduled_jobs', ['next_run_at'], unique=False)

    op.create_table(
        'scheduled_job_runs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('job_id', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='running'),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('result_ref', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['job_id'], ['scheduled_jobs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scheduled_job_runs_id'), 'scheduled_job_runs', ['id'], unique=False)
    op.create_index(op.f('ix_scheduled_job_runs_job_id'), 'scheduled_job_runs', ['job_id'], unique=False)
    op.create_index(op.f('ix_scheduled_job_runs_started_at'), 'scheduled_job_runs', ['started_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scheduled_job_runs_started_at'), table_name='scheduled_job_runs')
    op.drop_index(op.f('ix_scheduled_job_runs_job_id'), table_name='scheduled_job_runs')
    op.drop_index(op.f('ix_scheduled_job_runs_id'), table_name='scheduled_job_runs')
    op.drop_table('scheduled_job_runs')

    op.drop_index(op.f('ix_scheduled_jobs_next_run_at'), table_name='scheduled_jobs')
    op.drop_index(op.f('ix_scheduled_jobs_enabled'), table_name='scheduled_jobs')
    op.drop_index(op.f('ix_scheduled_jobs_asset_id'), table_name='scheduled_jobs')
    op.drop_index(op.f('ix_scheduled_jobs_job_type'), table_name='scheduled_jobs')
    op.drop_index(op.f('ix_scheduled_jobs_id'), table_name='scheduled_jobs')
    op.drop_table('scheduled_jobs')
