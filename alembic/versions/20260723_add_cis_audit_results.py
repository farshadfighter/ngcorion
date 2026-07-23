"""add cis_audit_results table

Revision ID: 20260723_cisres
Revises: 20260711_hvdom
Create Date: 2026-07-23

Adds the ``cis_audit_results`` table that stores per-check results produced by
the self-contained CIS benchmark services under ``app/cis/services/*`` (MongoDB
first). One row per (host, service, check) evaluation; a fresh audit inserts a
new set of rows so history is retained and callers pick the latest run.

Note: the foreign key targets ``asset_inventory.id`` — the project's real asset
table — rather than a table literally named ``assets``. No existing table is
modified.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '20260723_cisres'
down_revision: Union[str, Sequence[str], None] = '20260711_hvdom'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'cis_audit_results',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            'host_id', sa.Integer(),
            sa.ForeignKey('asset_inventory.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('check_id', sa.String(length=20), nullable=False),
        sa.Column('check_title', sa.String(length=255), nullable=False),
        sa.Column('service', sa.String(length=50), nullable=False),
        sa.Column('section', sa.String(length=10), nullable=False),
        sa.Column('scored', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('current_value', sa.Text(), nullable=True),
        sa.Column('expected_value', sa.Text(), nullable=True),
        sa.Column('fix_applied', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('error_msg', sa.Text(), nullable=True),
        sa.Column(
            'audited_at', sa.DateTime(timezone=True),
            nullable=False, server_default=sa.text('now()'),
        ),
        sa.Column('fixed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_cis_audit_results_host_id', 'cis_audit_results', ['host_id'])
    op.create_index('ix_cis_audit_results_host_service', 'cis_audit_results', ['host_id', 'service'])
    op.create_index('ix_cis_audit_results_host_status', 'cis_audit_results', ['host_id', 'status'])


def downgrade() -> None:
    op.drop_index('ix_cis_audit_results_host_status', table_name='cis_audit_results')
    op.drop_index('ix_cis_audit_results_host_service', table_name='cis_audit_results')
    op.drop_index('ix_cis_audit_results_host_id', table_name='cis_audit_results')
    op.drop_table('cis_audit_results')
