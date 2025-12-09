"""add port and protocol tables and update discovery_scans

Revision ID: a843df816d1c
Revises: 62b6732be89b
Create Date: 2025-12-09 15:54:12.264391

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a843df816d1c'
down_revision: Union[str, Sequence[str], None] = '62b6732be89b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    from sqlalchemy import inspect
    from datetime import datetime

    # Get bind and inspector
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_tables = inspector.get_table_names()

    # Create protocols table if it doesn't exist
    if 'protocols' not in existing_tables:
        op.create_table(
            'protocols',
            sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Protocol ID'),
            sa.Column('name', sa.String(20), nullable=False, comment='Protocol name (TCP, UDP, SCTP, etc.)'),
            sa.Column('description', sa.String(200), nullable=True, comment='Protocol description'),
            sa.Column('created_at', sa.DateTime(), nullable=True, comment='Record creation timestamp'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('name')
        )
        op.create_index('ix_protocols_name', 'protocols', ['name'])

    # Create ports table if it doesn't exist
    if 'ports' not in existing_tables:
        op.create_table(
            'ports',
            sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Port record ID'),
            sa.Column('asset_id', sa.Integer(), nullable=False, comment='Asset this port belongs to'),
            sa.Column('port_number', sa.Integer(), nullable=False, comment='Port number (1-65535)'),
            sa.Column('protocol_id', sa.Integer(), nullable=False, comment='Protocol type (TCP, UDP, etc.)'),
            sa.Column('service_name', sa.String(100), nullable=True, comment='Service name (http, ssh, mysql, etc.)'),
            sa.Column('service_product', sa.String(100), nullable=True, comment='Product name (nginx, Apache, OpenSSH, etc.)'),
            sa.Column('service_version', sa.String(100), nullable=True, comment='Service version'),
            sa.Column('state', sa.String(20), nullable=True, server_default='open', comment='Port state: open, closed, filtered'),
            sa.Column('discovered_by_scan_id', sa.String(50), nullable=True, comment='Scan that discovered this port'),
            sa.Column('is_active', sa.Boolean(), nullable=True, server_default='true', comment='Whether this port is currently active'),
            sa.Column('notes', sa.Text(), nullable=True, comment='Additional notes about this port'),
            sa.Column('discovered_at', sa.DateTime(), nullable=True, comment='When this port was first discovered'),
            sa.Column('updated_at', sa.DateTime(), nullable=True, comment='Last update timestamp'),
            sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['protocol_id'], ['protocols.id'], ondelete='RESTRICT'),
            sa.ForeignKeyConstraint(['discovered_by_scan_id'], ['discovery_scans.scan_id'], ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index('ix_ports_asset_id', 'ports', ['asset_id'])
        op.create_index('ix_ports_port_number', 'ports', ['port_number'])
        op.create_index('ix_ports_protocol_id', 'ports', ['protocol_id'])

    # Check if job_name column already exists
    discovery_scans_columns = [col['name'] for col in inspector.get_columns('discovery_scans')]
    if 'job_name' not in discovery_scans_columns:
        # Add job_name column to discovery_scans
        op.add_column(
            'discovery_scans',
            sa.Column(
                'job_name',
                sa.String(200),
                nullable=True,
                comment="User-friendly job name for the scan"
            )
        )
        op.create_index('ix_discovery_scans_job_name', 'discovery_scans', ['job_name'])

    # Seed initial protocol data if protocols table is empty
    result = bind.execute(sa.text("SELECT COUNT(*) FROM protocols"))
    count = result.scalar()
    if count == 0:
        bind.execute(
            sa.text(
                """
                INSERT INTO protocols (name, description, created_at)
                VALUES
                    ('TCP', 'Transmission Control Protocol', :now1),
                    ('UDP', 'User Datagram Protocol', :now2),
                    ('SCTP', 'Stream Control Transmission Protocol', :now3)
                """
            ),
            {'now1': datetime.utcnow(), 'now2': datetime.utcnow(), 'now3': datetime.utcnow()}
        )


def downgrade() -> None:
    """Downgrade schema."""
    # Remove job_name from discovery_scans
    op.drop_index('ix_discovery_scans_job_name', 'discovery_scans')
    op.drop_column('discovery_scans', 'job_name')

    # Drop ports table
    op.drop_index('ix_ports_protocol_id', 'ports')
    op.drop_index('ix_ports_port_number', 'ports')
    op.drop_index('ix_ports_asset_id', 'ports')
    op.drop_table('ports')

    # Drop protocols table
    op.drop_index('ix_protocols_name', 'protocols')
    op.drop_table('protocols')
