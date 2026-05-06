"""add security audit logs

Revision ID: f9a3c7e8d2b1
Revises: e4de134c385b
Create Date: 2025-01-XX XX:XX:XX.XXXXXX

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f9a3c7e8d2b1'
down_revision = 'e4de134c385b'
branch_labels = None
depends_on = None


def upgrade():
    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Unique log entry ID'),
        sa.Column('user_id', sa.Integer(), nullable=True, comment='User who performed the action (nullable for anonymous/system actions)'),
        sa.Column('username', sa.String(length=100), nullable=True, comment='Username at time of action (preserved even if user deleted)'),
        sa.Column('action', sa.String(length=100), nullable=False, comment="Action performed (e.g., 'user.create', 'asset.delete', 'permission.update')"),
        sa.Column('module', sa.String(length=50), nullable=True, comment="Module where action occurred (e.g., 'user_management', 'asset_list')"),
        sa.Column('target_id', sa.Integer(), nullable=True, comment='ID of the affected resource (e.g., user_id, asset_id)'),
        sa.Column('ip_address', sa.String(length=50), nullable=True, comment='IP address of the requester'),
        sa.Column('result', sa.String(length=20), nullable=False, server_default='success', comment="Result of the action ('success' or 'failure')"),
        sa.Column('detail', sa.Text(), nullable=True, comment='Additional context or error message'),
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='When the action occurred'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for common queries
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_username', 'audit_logs', ['username'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_module', 'audit_logs', ['module'])
    op.create_index('ix_audit_logs_ip_address', 'audit_logs', ['ip_address'])
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])


def downgrade():
    # Drop indexes
    op.drop_index('ix_audit_logs_timestamp', table_name='audit_logs')
    op.drop_index('ix_audit_logs_ip_address', table_name='audit_logs')
    op.drop_index('ix_audit_logs_module', table_name='audit_logs')
    op.drop_index('ix_audit_logs_action', table_name='audit_logs')
    op.drop_index('ix_audit_logs_username', table_name='audit_logs')
    op.drop_index('ix_audit_logs_user_id', table_name='audit_logs')
    
    # Drop table
    op.drop_table('audit_logs')
