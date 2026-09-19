"""add design and configuration tables

Revision ID: b7f3d5a9c2e1
Revises: a2c6e9f1b7d4
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7f3d5a9c2e1'
down_revision: Union[str, Sequence[str], None] = 'a2c6e9f1b7d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'architecture_designs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='draft'),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_architecture_designs_id'), 'architecture_designs', ['id'], unique=False)
    op.create_index(op.f('ix_architecture_designs_created_at'), 'architecture_designs', ['created_at'], unique=False)

    op.create_table(
        'architecture_design_versions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('design_id', sa.Integer(), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['design_id'], ['architecture_designs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('design_id', 'version_number', name='uq_design_version_number'),
    )
    op.create_index(op.f('ix_architecture_design_versions_id'), 'architecture_design_versions', ['id'], unique=False)
    op.create_index(op.f('ix_architecture_design_versions_design_id'), 'architecture_design_versions', ['design_id'], unique=False)
    op.create_index(op.f('ix_architecture_design_versions_created_at'), 'architecture_design_versions', ['created_at'], unique=False)

    op.create_table(
        'design_components',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('design_version_id', sa.Integer(), nullable=False),
        sa.Column('component_type', sa.String(length=50), nullable=False, server_default='server'),
        sa.Column('label', sa.String(length=200), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('pos_x', sa.Float(), nullable=False, server_default='0'),
        sa.Column('pos_y', sa.Float(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['design_version_id'], ['architecture_design_versions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_design_components_id'), 'design_components', ['id'], unique=False)
    op.create_index(op.f('ix_design_components_design_version_id'), 'design_components', ['design_version_id'], unique=False)

    op.create_table(
        'design_relationships',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('design_version_id', sa.Integer(), nullable=False),
        sa.Column('source_component_id', sa.Integer(), nullable=False),
        sa.Column('destination_component_id', sa.Integer(), nullable=False),
        sa.Column('source_interface', sa.String(length=50), nullable=True),
        sa.Column('destination_interface', sa.String(length=50), nullable=True),
        sa.Column('link_type', sa.String(length=30), nullable=False, server_default='ethernet'),
        sa.Column('vlan', sa.String(length=20), nullable=True),
        sa.Column('subnet', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['design_version_id'], ['architecture_design_versions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['source_component_id'], ['design_components.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['destination_component_id'], ['design_components.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_design_relationships_id'), 'design_relationships', ['id'], unique=False)
    op.create_index(op.f('ix_design_relationships_design_version_id'), 'design_relationships', ['design_version_id'], unique=False)

    op.create_table(
        'design_asset_mappings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('design_component_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('mapped_by', sa.Integer(), nullable=True),
        sa.Column('mapped_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['design_component_id'], ['design_components.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['mapped_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('design_component_id', name='uq_design_asset_mapping_component'),
    )
    op.create_index(op.f('ix_design_asset_mappings_id'), 'design_asset_mappings', ['id'], unique=False)
    op.create_index(op.f('ix_design_asset_mappings_design_component_id'), 'design_asset_mappings', ['design_component_id'], unique=False)
    op.create_index(op.f('ix_design_asset_mappings_asset_id'), 'design_asset_mappings', ['asset_id'], unique=False)

    op.create_table(
        'configuration_jobs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('design_version_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='generated'),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['design_version_id'], ['architecture_design_versions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_configuration_jobs_id'), 'configuration_jobs', ['id'], unique=False)
    op.create_index(op.f('ix_configuration_jobs_design_version_id'), 'configuration_jobs', ['design_version_id'], unique=False)
    op.create_index(op.f('ix_configuration_jobs_created_at'), 'configuration_jobs', ['created_at'], unique=False)

    op.create_table(
        'configuration_objects',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('configuration_job_id', sa.Integer(), nullable=False),
        sa.Column('design_component_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('asset_name', sa.String(length=200), nullable=True),
        sa.Column('device_type', sa.String(length=30), nullable=True),
        sa.Column('generated_config', sa.Text(), nullable=False),
        sa.Column('apply_status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('apply_output', sa.Text(), nullable=True),
        sa.Column('applied_by', sa.Integer(), nullable=True),
        sa.Column('applied_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['configuration_job_id'], ['configuration_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['design_component_id'], ['design_components.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['applied_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_configuration_objects_id'), 'configuration_objects', ['id'], unique=False)
    op.create_index(op.f('ix_configuration_objects_configuration_job_id'), 'configuration_objects', ['configuration_job_id'], unique=False)
    op.create_index(op.f('ix_configuration_objects_asset_id'), 'configuration_objects', ['asset_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_configuration_objects_asset_id'), table_name='configuration_objects')
    op.drop_index(op.f('ix_configuration_objects_configuration_job_id'), table_name='configuration_objects')
    op.drop_index(op.f('ix_configuration_objects_id'), table_name='configuration_objects')
    op.drop_table('configuration_objects')

    op.drop_index(op.f('ix_configuration_jobs_created_at'), table_name='configuration_jobs')
    op.drop_index(op.f('ix_configuration_jobs_design_version_id'), table_name='configuration_jobs')
    op.drop_index(op.f('ix_configuration_jobs_id'), table_name='configuration_jobs')
    op.drop_table('configuration_jobs')

    op.drop_index(op.f('ix_design_asset_mappings_asset_id'), table_name='design_asset_mappings')
    op.drop_index(op.f('ix_design_asset_mappings_design_component_id'), table_name='design_asset_mappings')
    op.drop_index(op.f('ix_design_asset_mappings_id'), table_name='design_asset_mappings')
    op.drop_table('design_asset_mappings')

    op.drop_index(op.f('ix_design_relationships_design_version_id'), table_name='design_relationships')
    op.drop_index(op.f('ix_design_relationships_id'), table_name='design_relationships')
    op.drop_table('design_relationships')

    op.drop_index(op.f('ix_design_components_design_version_id'), table_name='design_components')
    op.drop_index(op.f('ix_design_components_id'), table_name='design_components')
    op.drop_table('design_components')

    op.drop_index(op.f('ix_architecture_design_versions_created_at'), table_name='architecture_design_versions')
    op.drop_index(op.f('ix_architecture_design_versions_design_id'), table_name='architecture_design_versions')
    op.drop_index(op.f('ix_architecture_design_versions_id'), table_name='architecture_design_versions')
    op.drop_table('architecture_design_versions')

    op.drop_index(op.f('ix_architecture_designs_created_at'), table_name='architecture_designs')
    op.drop_index(op.f('ix_architecture_designs_id'), table_name='architecture_designs')
    op.drop_table('architecture_designs')
