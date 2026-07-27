"""add_risk_module_tables

Revision ID: 931114c3a14b
Revises: 20260723_cisres
Create Date: 2026-07-27 16:12:34.204851

Adds the Risk & Exposure Intelligence tables: risk_settings, risk_zones,
asset_risk_profiles, asset_open_ports, asset_risk_scores, asset_risk_history,
risk_calculation_logs.

Note: unrelated autogenerate drift (comment changes, drops of tables managed
outside app.models such as cis_audit_results / audit_module_logs) was removed
by hand — this revision only creates the risk module tables.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '931114c3a14b'
down_revision: Union[str, Sequence[str], None] = '20260723_cisres'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('risk_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('setting_key', sa.String(length=100), nullable=False),
    sa.Column('setting_value', sa.String(length=255), nullable=False),
    sa.Column('value_type', sa.String(length=20), nullable=False),
    sa.Column('description', sa.String(length=500), nullable=True),
    sa.Column('is_editable', sa.Boolean(), nullable=False),
    sa.Column('updated_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_risk_settings_id'), 'risk_settings', ['id'], unique=False)
    op.create_index(op.f('ix_risk_settings_setting_key'), 'risk_settings', ['setting_key'], unique=True)
    op.create_table('risk_zones',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.String(length=500), nullable=True),
    sa.Column('score', sa.Numeric(precision=5, scale=2), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('updated_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_risk_zones_id'), 'risk_zones', ['id'], unique=False)
    op.create_table('asset_open_ports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('ip_address', sa.String(length=50), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=20), nullable=False),
    sa.Column('service_name', sa.String(length=100), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('severity_score', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('source', sa.String(length=50), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('is_approved', sa.Boolean(), nullable=False),
    sa.Column('is_included_in_risk', sa.Boolean(), nullable=False),
    sa.Column('exclusion_reason', sa.String(length=500), nullable=True),
    sa.Column('updated_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('asset_id', 'ip_address', 'port', 'protocol', name='uq_asset_open_ports_asset_ip_port_proto')
    )
    op.create_index(op.f('ix_asset_open_ports_asset_id'), 'asset_open_ports', ['asset_id'], unique=False)
    op.create_index('ix_asset_open_ports_asset_included', 'asset_open_ports', ['asset_id', 'is_included_in_risk'], unique=False)
    op.create_index('ix_asset_open_ports_asset_status', 'asset_open_ports', ['asset_id', 'status'], unique=False)
    op.create_index(op.f('ix_asset_open_ports_id'), 'asset_open_ports', ['id'], unique=False)
    op.create_table('asset_risk_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('risk_score', sa.Numeric(precision=5, scale=2), nullable=False),
    sa.Column('risk_level', sa.String(length=20), nullable=False),
    sa.Column('criticality_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('zone_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('open_port_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('audit_risk_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('criticality_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('zone_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('open_port_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('audit_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('audit_id', sa.Integer(), nullable=True),
    sa.Column('reason', sa.String(length=255), nullable=True),
    sa.Column('calculated_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_asset_risk_history_asset_calculated', 'asset_risk_history', ['asset_id', sa.literal_column('calculated_at DESC')], unique=False)
    op.create_index(op.f('ix_asset_risk_history_asset_id'), 'asset_risk_history', ['asset_id'], unique=False)
    op.create_index(op.f('ix_asset_risk_history_id'), 'asset_risk_history', ['id'], unique=False)
    op.create_table('asset_risk_profiles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('criticality_level', sa.String(length=30), nullable=False),
    sa.Column('criticality_score', sa.Numeric(precision=5, scale=2), nullable=False),
    sa.Column('zone_id', sa.Integer(), nullable=True),
    sa.Column('criticality_is_default', sa.Boolean(), nullable=False),
    sa.Column('zone_is_default', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('updated_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['zone_id'], ['risk_zones.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_risk_profiles_asset_id'), 'asset_risk_profiles', ['asset_id'], unique=True)
    op.create_index(op.f('ix_asset_risk_profiles_id'), 'asset_risk_profiles', ['id'], unique=False)
    op.create_table('asset_risk_scores',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('criticality_level', sa.String(length=30), nullable=True),
    sa.Column('criticality_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('criticality_weight', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('criticality_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('zone_id', sa.Integer(), nullable=True),
    sa.Column('zone_name', sa.String(length=100), nullable=True),
    sa.Column('zone_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('zone_weight', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('zone_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('open_port_raw_score', sa.Numeric(precision=8, scale=2), nullable=True),
    sa.Column('open_port_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('open_port_weight', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('open_port_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('audit_failed_weight', sa.Numeric(precision=8, scale=2), nullable=True),
    sa.Column('audit_applicable_weight', sa.Numeric(precision=8, scale=2), nullable=True),
    sa.Column('audit_risk_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('audit_weight', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('audit_contribution', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('final_risk_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('risk_level', sa.String(length=20), nullable=True),
    sa.Column('critical_findings_count', sa.Integer(), nullable=False),
    sa.Column('high_findings_count', sa.Integer(), nullable=False),
    sa.Column('medium_findings_count', sa.Integer(), nullable=False),
    sa.Column('low_findings_count', sa.Integer(), nullable=False),
    sa.Column('open_ports_count', sa.Integer(), nullable=False),
    sa.Column('risky_ports_count', sa.Integer(), nullable=False),
    sa.Column('resolved_by_hardening_count', sa.Integer(), nullable=False),
    sa.Column('active_audit_findings_count', sa.Integer(), nullable=False),
    sa.Column('incomplete_data', sa.Boolean(), nullable=False),
    sa.Column('incomplete_reasons_json', sa.JSON(), nullable=True),
    sa.Column('audit_id', sa.Integer(), nullable=True),
    sa.Column('calculated_at', sa.DateTime(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['zone_id'], ['risk_zones.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_risk_scores_asset_id'), 'asset_risk_scores', ['asset_id'], unique=True)
    op.create_index('ix_asset_risk_scores_final_desc', 'asset_risk_scores', [sa.literal_column('final_risk_score DESC')], unique=False)
    op.create_index(op.f('ix_asset_risk_scores_id'), 'asset_risk_scores', ['id'], unique=False)
    op.create_index('ix_asset_risk_scores_risk_level', 'asset_risk_scores', ['risk_level'], unique=False)
    op.create_table('risk_calculation_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=True),
    sa.Column('calculation_status', sa.String(length=30), nullable=False),
    sa.Column('input_json', sa.JSON(), nullable=True),
    sa.Column('output_json', sa.JSON(), nullable=True),
    sa.Column('error_message', sa.String(length=2000), nullable=True),
    sa.Column('trigger_type', sa.String(length=50), nullable=False),
    sa.Column('trigger_reference_id', sa.Integer(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_risk_calculation_logs_asset_id'), 'risk_calculation_logs', ['asset_id'], unique=False)
    op.create_index(op.f('ix_risk_calculation_logs_id'), 'risk_calculation_logs', ['id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_risk_calculation_logs_id'), table_name='risk_calculation_logs')
    op.drop_index(op.f('ix_risk_calculation_logs_asset_id'), table_name='risk_calculation_logs')
    op.drop_table('risk_calculation_logs')
    op.drop_index('ix_asset_risk_scores_risk_level', table_name='asset_risk_scores')
    op.drop_index(op.f('ix_asset_risk_scores_id'), table_name='asset_risk_scores')
    op.drop_index('ix_asset_risk_scores_final_desc', table_name='asset_risk_scores')
    op.drop_index(op.f('ix_asset_risk_scores_asset_id'), table_name='asset_risk_scores')
    op.drop_table('asset_risk_scores')
    op.drop_index(op.f('ix_asset_risk_profiles_id'), table_name='asset_risk_profiles')
    op.drop_index(op.f('ix_asset_risk_profiles_asset_id'), table_name='asset_risk_profiles')
    op.drop_table('asset_risk_profiles')
    op.drop_index(op.f('ix_asset_risk_history_id'), table_name='asset_risk_history')
    op.drop_index(op.f('ix_asset_risk_history_asset_id'), table_name='asset_risk_history')
    op.drop_index('ix_asset_risk_history_asset_calculated', table_name='asset_risk_history')
    op.drop_table('asset_risk_history')
    op.drop_index(op.f('ix_asset_open_ports_id'), table_name='asset_open_ports')
    op.drop_index('ix_asset_open_ports_asset_status', table_name='asset_open_ports')
    op.drop_index('ix_asset_open_ports_asset_included', table_name='asset_open_ports')
    op.drop_index(op.f('ix_asset_open_ports_asset_id'), table_name='asset_open_ports')
    op.drop_table('asset_open_ports')
    op.drop_index(op.f('ix_risk_zones_id'), table_name='risk_zones')
    op.drop_table('risk_zones')
    op.drop_index(op.f('ix_risk_settings_setting_key'), table_name='risk_settings')
    op.drop_index(op.f('ix_risk_settings_id'), table_name='risk_settings')
    op.drop_table('risk_settings')
