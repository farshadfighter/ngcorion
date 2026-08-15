"""add system_config_settings table and SYSTEM_CONFIG module permission

Revision ID: c7e1b93a5d02
Revises: d4f6a8b0c2e1
Create Date: 2026-08-15

Creates the single generic table backing every System Configuration section
(time/snmp/syslog/sms/smtp — one row each, payload in config_json) and adds the
SYSTEM_CONFIG value to the moduleenum type so user_permissions rows can grant
read/write on the module, exactly as RISK was added in a4c2d91e7b30.

The enum value is added in an autocommit block: PostgreSQL forbids using a new
enum value in the same transaction that added it, and older servers forbid
ALTER TYPE ... ADD VALUE inside a transaction entirely.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c7e1b93a5d02'
down_revision: Union[str, Sequence[str], None] = 'd4f6a8b0c2e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'SYSTEM_CONFIG'")

    op.create_table(
        'system_config_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('section', sa.String(length=50), nullable=False),
        sa.Column('config_json', sa.JSON(), nullable=False),
        sa.Column('updated_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_system_config_settings_id'),
        'system_config_settings', ['id'], unique=False,
    )
    op.create_index(
        op.f('ix_system_config_settings_section'),
        'system_config_settings', ['section'], unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        op.f('ix_system_config_settings_section'),
        table_name='system_config_settings',
    )
    op.drop_index(
        op.f('ix_system_config_settings_id'),
        table_name='system_config_settings',
    )
    op.drop_table('system_config_settings')
    # PostgreSQL cannot remove a value from an enum type; leaving 'SYSTEM_CONFIG'
    # in place is harmless once user_permissions rows referencing it are gone.
