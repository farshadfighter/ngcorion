"""add hardening actions table

Revision ID: a5f152b811da
Revises: d71e1a4f5f3b
Create Date: 2025-12-22 19:11:04.915330

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a5f152b811da'
down_revision: Union[str, Sequence[str], None] = 'd71e1a4f5f3b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create hardening_actions table."""
    op.create_table(
        'hardening_actions',
        sa.Column('id', sa.Integer(), nullable=False),

        # Foreign keys
        sa.Column('audit_result_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('audit_session_id', sa.Integer(), nullable=False),

        # Action metadata
        sa.Column('check_number', sa.String(length=20), nullable=False),
        sa.Column('check_title', sa.String(length=500), nullable=False),
        sa.Column('action_type', sa.String(length=10), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),

        # Command details
        sa.Column('commands_json', sa.Text(), nullable=False),
        sa.Column('requires_config_mode', sa.Boolean(), nullable=True),

        # Execution details
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('backup_config', sa.Text(), nullable=True),
        sa.Column('verification_passed', sa.Boolean(), nullable=True),
        sa.Column('verification_evidence', sa.Text(), nullable=True),

        # Error tracking
        sa.Column('error_message', sa.Text(), nullable=True),

        # Credentials tracking
        sa.Column('credentials_provided', sa.Boolean(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('executed_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),

        # Primary key
        sa.PrimaryKeyConstraint('id'),

        # Foreign key constraints
        sa.ForeignKeyConstraint(['audit_result_id'], ['audit_results.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id']),
        sa.ForeignKeyConstraint(['audit_session_id'], ['audit_sessions.id'], ondelete='CASCADE'),
    )

    # Create indexes for better query performance
    op.create_index('ix_hardening_actions_id', 'hardening_actions', ['id'])
    op.create_index('ix_hardening_actions_audit_result_id', 'hardening_actions', ['audit_result_id'])
    op.create_index('ix_hardening_actions_user_id', 'hardening_actions', ['user_id'])
    op.create_index('ix_hardening_actions_asset_id', 'hardening_actions', ['asset_id'])
    op.create_index('ix_hardening_actions_audit_session_id', 'hardening_actions', ['audit_session_id'])
    op.create_index('ix_hardening_actions_check_number', 'hardening_actions', ['check_number'])
    op.create_index('ix_hardening_actions_status', 'hardening_actions', ['status'])
    op.create_index('ix_hardening_actions_created_at', 'hardening_actions', ['created_at'])


def downgrade() -> None:
    """Drop hardening_actions table."""
    # Drop indexes first
    op.drop_index('ix_hardening_actions_created_at', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_status', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_check_number', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_audit_session_id', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_asset_id', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_user_id', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_audit_result_id', table_name='hardening_actions')
    op.drop_index('ix_hardening_actions_id', table_name='hardening_actions')

    # Drop table
    op.drop_table('hardening_actions')
