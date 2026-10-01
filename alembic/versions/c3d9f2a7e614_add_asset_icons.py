"""add icon to asset_types and asset_inventory

Revision ID: c3d9f2a7e614
Revises: b7e2c4a91d30
Create Date: 2026-10-01 04:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "c3d9f2a7e614"
down_revision = "b7e2c4a91d30"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_types", sa.Column("icon", sa.String(length=32), nullable=True,
                                           comment="Icon key used to draw assets of this type"))
    op.add_column("asset_inventory", sa.Column("icon", sa.String(length=32), nullable=True,
                                               comment="Icon key override for this asset"))


def downgrade() -> None:
    op.drop_column("asset_inventory", "icon")
    op.drop_column("asset_types", "icon")
