"""add module audit logs

Revision ID: add_module_audit_logs
Revises: 66987062eb68
Create Date: 2025-12-31

Creates three separate audit log tables:
- asset_requirement_logs: For asset requirement module
- asset_logs: For asset list module
- audit_module_logs: For audit (CIS) module
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'add_module_audit_logs'
down_revision: Union[str, Sequence[str], None] = '66987062eb68'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create asset_requirement_logs table
    op.create_table('asset_requirement_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True, comment='User who performed the action'),
        sa.Column('action', sa.String(length=64), nullable=False, comment='Action type: create, update, delete, excel_import'),
        sa.Column('entity_type', sa.String(length=64), nullable=False, comment='Entity type: asset_type, owner, location, zone, os_catalog, vendor'),
        sa.Column('entity_id', sa.Integer(), nullable=True, comment='ID of the affected entity'),
        sa.Column('entity_name', sa.String(length=256), nullable=True, comment='Name of the affected entity'),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Additional context'),
        sa.Column('status', sa.String(length=32), nullable=True, comment='Status: success, failed, partial'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error details if failed'),
        sa.Column('timestamp', sa.DateTime(), nullable=True, comment='When the action occurred'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_asset_requirement_logs_user_id', 'asset_requirement_logs', ['user_id'])
    op.create_index('ix_asset_requirement_logs_action', 'asset_requirement_logs', ['action'])
    op.create_index('ix_asset_requirement_logs_entity_type', 'asset_requirement_logs', ['entity_type'])
    op.create_index('ix_asset_requirement_logs_entity_id', 'asset_requirement_logs', ['entity_id'])
    op.create_index('ix_asset_requirement_logs_timestamp', 'asset_requirement_logs', ['timestamp'])

    # Create asset_logs table
    op.create_table('asset_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True, comment='User who performed the action'),
        sa.Column('action', sa.String(length=64), nullable=False, comment='Action type: create, update, delete, excel_import'),
        sa.Column('asset_id', sa.Integer(), nullable=True, comment='ID of the affected asset'),
        sa.Column('asset_name', sa.String(length=256), nullable=True, comment='Name of the affected asset'),
        sa.Column('ip_address', sa.String(length=64), nullable=True, comment='IP address of the asset'),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Additional context'),
        sa.Column('status', sa.String(length=32), nullable=True, comment='Status: success, failed'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error details if failed'),
        sa.Column('timestamp', sa.DateTime(), nullable=True, comment='When the action occurred'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_asset_logs_user_id', 'asset_logs', ['user_id'])
    op.create_index('ix_asset_logs_action', 'asset_logs', ['action'])
    op.create_index('ix_asset_logs_asset_id', 'asset_logs', ['asset_id'])
    op.create_index('ix_asset_logs_ip_address', 'asset_logs', ['ip_address'])
    op.create_index('ix_asset_logs_timestamp', 'asset_logs', ['timestamp'])

    # Create audit_module_logs table
    op.create_table('audit_module_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True, comment='User who performed the action'),
        sa.Column('action', sa.String(length=64), nullable=False, comment='Action type: execute_audit, delete_session'),
        sa.Column('session_id', sa.Integer(), nullable=True, comment='ID of the audit session'),
        sa.Column('asset_id', sa.Integer(), nullable=True, comment='ID of the target asset'),
        sa.Column('asset_name', sa.String(length=256), nullable=True, comment='Name of the target asset'),
        sa.Column('target_ip', sa.String(length=64), nullable=True, comment='Target IP address'),
        sa.Column('audit_type', sa.String(length=64), nullable=True, comment='Audit type: cisco_cis, cis_benchmark'),
        sa.Column('profile', sa.String(length=32), nullable=True, comment='CIS profile: L1, FULL'),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Additional context'),
        sa.Column('status', sa.String(length=32), nullable=True, comment='Status: success, failed'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error details if failed'),
        sa.Column('timestamp', sa.DateTime(), nullable=True, comment='When the action occurred'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_module_logs_user_id', 'audit_module_logs', ['user_id'])
    op.create_index('ix_audit_module_logs_action', 'audit_module_logs', ['action'])
    op.create_index('ix_audit_module_logs_session_id', 'audit_module_logs', ['session_id'])
    op.create_index('ix_audit_module_logs_asset_id', 'audit_module_logs', ['asset_id'])
    op.create_index('ix_audit_module_logs_timestamp', 'audit_module_logs', ['timestamp'])


def downgrade() -> None:
    op.drop_table('audit_module_logs')
    op.drop_table('asset_logs')
    op.drop_table('asset_requirement_logs')
