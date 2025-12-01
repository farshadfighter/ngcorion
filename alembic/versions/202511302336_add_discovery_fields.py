"""
add discovery_fields to asset_inventory

Revision ID: c9f1e2d3a4b5
Revises: b8ae20bc6d1a
Create Date: 2025-01-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = 'c9f1e2d3a4b5'
down_revision = 'b8ae20bc6d1a'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'asset_inventory',
        sa.Column(
            'discovered_fields',
            JSON,
            nullable=True,
            server_default='{}',
            comment="Fields populated by auto-discovery"
        )
    )


def downgrade():
    op.drop_column('asset_inventory', 'discovered_fields')
