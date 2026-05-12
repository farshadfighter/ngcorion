"""add hardening logs table

Revision ID: 20260512_034258
Revises: e4de134c385b
Create Date: 2026-05-12 03:42:58

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '20260512_034258'
down_revision: Union[str, Sequence[str], None] = 'e4de134c385b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create hardening_logs table."""
    op.create_table(
        'hardening_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True, comment='User who performed the action'),
        sa.Column('action', sa.String(length=64), nullable=False, comment='Action type: preview, execute, batch_execute, auto_harden'),
        sa.Column('asset_id', sa.Integer(), nullable=True, comment='ID of the affected asset'),
        sa.Column('asset_name', sa.String(length=256), nullable=True, comment='Name of the affected asset for readability'),
        sa.Column('audit_session_id', sa.Integer(), nullable=True, comment='Related audit session'),
        sa.Column('device_type', sa.String(length=50), nullable=True, comment='Device type: cisco, fortinet, linux, apache, windows, mssql, mongodb'),
        sa.Column('check_ids', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='List of check IDs involved in this operation'),
        sa.Column('check_count', sa.Integer(), nullable=True, comment='Number of checks processed'),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Additional context (parameters, warnings, etc.)'),
        sa.Column('status', sa.String(length=32), nullable=True, comment='Status: success, failed, partial'),
        sa.Column('success_count', sa.Integer(), nullable=True, comment='Number of successful operations'),
        sa.Column('failed_count', sa.Integer(), nullable=True, comment='Number of failed operations'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error details if failed'),
        sa.Column('timestamp', sa.DateTime(), nullable=True, comment='When the action occurred'),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['audit_session_id'], ['audit_sessions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index(op.f('ix_hardening_logs_user_id'), 'hardening_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_hardening_logs_action'), 'hardening_logs', ['action'], unique=False)
    op.create_index(op.f('ix_hardening_logs_asset_id'), 'hardening_logs', ['asset_id'], unique=False)
    op.create_index(op.f('ix_hardening_logs_audit_session_id'), 'hardening_logs', ['audit_session_id'], unique=False)
    op.create_index(op.f('ix_hardening_logs_device_type'), 'hardening_logs', ['device_type'], unique=False)
    op.create_index(op.f('ix_hardening_logs_status'), 'hardening_logs', ['status'], unique=False)
    op.create_index(op.f('ix_hardening_logs_timestamp'), 'hardening_logs', ['timestamp'], unique=False)


def downgrade() -> None:
    """Drop hardening_logs table."""
    op.drop_index(op.f('ix_hardening_logs_timestamp'), table_name='hardening_logs')
    op.drop_index(op.f('ix_hardening_logs_status'), table_name='hardening_logs')
    op.drop_index(op.f('ix_hardening_logs_device_type'), table_name='hardening_logs')
    op.drop_index(op.f('ix_hardening_logs_audit_session_id'), table_name='hardening_logs')
    op.drop_index(op.f('ix_hardening_logs_asset_id'), table_name='hardening_logs')
    op.drop_index(op.f('ix_hardening_logs_action'), table_name='hardening_logs')
    op.drop_index(op.f('ix_hardening_logs_user_id'), table_name='hardening_logs')
    op.drop_table('hardening_logs')
