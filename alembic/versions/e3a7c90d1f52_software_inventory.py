"""software inventory: items, collections, changes, product mappings

Revision ID: e3a7c90d1f52
Revises: d91f5b7e2a40
Create Date: 2026-10-05 09:00:00.000000

See app/models/software.py. Viewing uses the asset list permission, so no
new permission module.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e3a7c90d1f52"
down_revision: Union[str, Sequence[str], None] = "d91f5b7e2a40"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "software_collections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector", sa.String(16), nullable=False),
        sa.Column("trigger", sa.String(10), nullable=False, server_default="audit"),
        sa.Column("audit_session_id", sa.Integer(), sa.ForeignKey("audit_sessions.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("collected_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(8), nullable=False, server_default="ok"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("item_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("added", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("removed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=True),
    )
    op.create_index("ix_software_collections_asset_id", "software_collections", ["asset_id"])
    op.create_index("ix_software_collections_collected_at", "software_collections", ["collected_at"])

    op.create_table(
        "software_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(12), nullable=False, server_default="package"),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("version", sa.String(160), nullable=True),
        sa.Column("arch", sa.String(60), nullable=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("origin", sa.String(200), nullable=True),
        sa.Column("publisher", sa.String(200), nullable=True),
        sa.Column("source_package", sa.String(200), nullable=True),
        sa.Column("vkind", sa.String(4), nullable=True),
        sa.Column("collection_id", sa.Integer(), sa.ForeignKey("software_collections.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_software_items_asset_id", "software_items", ["asset_id"])
    op.create_index("ix_software_items_name", "software_items", ["name"])
    op.create_index("ix_software_items_source", "software_items", ["source"])
    op.create_index("ix_software_items_asset_collector", "software_items", ["asset_id", "collector"])

    op.create_table(
        "software_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collection_id", sa.Integer(), sa.ForeignKey("software_collections.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("change", sa.String(8), nullable=False),
        sa.Column("kind", sa.String(12), nullable=False, server_default="package"),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("old_version", sa.String(160), nullable=True),
        sa.Column("new_version", sa.String(160), nullable=True),
        sa.Column("source", sa.String(16), nullable=True),
        sa.Column("origin", sa.String(200), nullable=True),
        sa.Column("at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_software_changes_asset_id", "software_changes", ["asset_id"])
    op.create_index("ix_software_changes_collection_id", "software_changes", ["collection_id"])
    op.create_index("ix_software_changes_at", "software_changes", ["at"])

    op.create_table(
        "software_product_maps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("match_key", sa.String(300), nullable=False, unique=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="cpe"),
        sa.Column("vendor", sa.String(120), nullable=True),
        sa.Column("product", sa.String(160), nullable=True),
        sa.Column("label", sa.String(200), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("software_product_maps")
    op.drop_table("software_changes")
    op.drop_table("software_items")
    op.drop_table("software_collections")
