"""add noc snmp monitoring tables

Revision ID: 3451824a39b2
Revises: b7c14e29f0a3
Create Date: 2026-09-20 07:26:43.234917

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '3451824a39b2'
down_revision: Union[str, Sequence[str], None] = 'b7c14e29f0a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'asset_snmp_credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('version', sa.String(length=10), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('community_encrypted', sa.Text(), nullable=True),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('auth_protocol', sa.String(length=20), nullable=True),
        sa.Column('auth_key_encrypted', sa.Text(), nullable=True),
        sa.Column('priv_protocol', sa.String(length=20), nullable=True),
        sa.Column('priv_key_encrypted', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_asset_snmp_credentials_asset_id'), 'asset_snmp_credentials', ['asset_id'], unique=True)
    op.create_index(op.f('ix_asset_snmp_credentials_id'), 'asset_snmp_credentials', ['id'], unique=False)

    op.create_table(
        'asset_snmp_interfaces',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('if_index', sa.Integer(), nullable=False),
        sa.Column('if_descr', sa.String(length=255), nullable=True),
        sa.Column('if_type', sa.Integer(), nullable=True),
        sa.Column('if_speed', sa.BigInteger(), nullable=True),
        sa.Column('if_admin_status', sa.String(length=20), nullable=True),
        sa.Column('if_oper_status', sa.String(length=20), nullable=True),
        sa.Column('in_octets', sa.BigInteger(), nullable=True),
        sa.Column('out_octets', sa.BigInteger(), nullable=True),
        sa.Column('last_polled_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id', 'if_index', name='uq_snmp_interface_asset_ifindex'),
    )
    op.create_index(op.f('ix_asset_snmp_interfaces_asset_id'), 'asset_snmp_interfaces', ['asset_id'], unique=False)
    op.create_index(op.f('ix_asset_snmp_interfaces_id'), 'asset_snmp_interfaces', ['id'], unique=False)

    op.create_table(
        'asset_snmp_status',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('reachable', sa.Boolean(), nullable=False),
        sa.Column('sys_descr', sa.Text(), nullable=True),
        sa.Column('sys_name', sa.String(length=255), nullable=True),
        sa.Column('sys_contact', sa.String(length=255), nullable=True),
        sa.Column('sys_location', sa.String(length=255), nullable=True),
        sa.Column('sys_uptime_ticks', sa.BigInteger(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('last_polled_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_asset_snmp_status_asset_id'), 'asset_snmp_status', ['asset_id'], unique=True)
    op.create_index(op.f('ix_asset_snmp_status_id'), 'asset_snmp_status', ['id'], unique=False)
    op.create_index(op.f('ix_asset_snmp_status_last_polled_at'), 'asset_snmp_status', ['last_polled_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_asset_snmp_status_last_polled_at'), table_name='asset_snmp_status')
    op.drop_index(op.f('ix_asset_snmp_status_id'), table_name='asset_snmp_status')
    op.drop_index(op.f('ix_asset_snmp_status_asset_id'), table_name='asset_snmp_status')
    op.drop_table('asset_snmp_status')

    op.drop_index(op.f('ix_asset_snmp_interfaces_id'), table_name='asset_snmp_interfaces')
    op.drop_index(op.f('ix_asset_snmp_interfaces_asset_id'), table_name='asset_snmp_interfaces')
    op.drop_table('asset_snmp_interfaces')

    op.drop_index(op.f('ix_asset_snmp_credentials_id'), table_name='asset_snmp_credentials')
    op.drop_index(op.f('ix_asset_snmp_credentials_asset_id'), table_name='asset_snmp_credentials')
    op.drop_table('asset_snmp_credentials')
