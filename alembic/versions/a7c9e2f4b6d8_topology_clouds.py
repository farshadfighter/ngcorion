"""Topology: external networks (clouds) and their links to devices

- topology_clouds: the Internet, MPLS, WAN, SD-WAN, LTE/4G backup, a public cloud or a partner network on
  the Topology canvas; not assets (no inventory, no license).
- topology_cloud_links: which device connects to it, on which interface, the circuit and its speed.

Revision ID: a7c9e2f4b6d8
Revises: f5a7c9e1b3d4
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7c9e2f4b6d8"
down_revision: Union[str, Sequence[str], None] = "f5a7c9e1b3d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "topology_clouds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=False),
        sa.Column("provider", sa.String(length=120), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("pos_x", sa.Float(), nullable=True),
        sa.Column("pos_y", sa.Float(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_topology_clouds_id", "topology_clouds", ["id"])
    op.create_table(
        "topology_cloud_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cloud_id", sa.Integer(), sa.ForeignKey("topology_clouds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("interface", sa.String(length=100), nullable=True),
        sa.Column("circuit_id", sa.String(length=100), nullable=True),
        sa.Column("speed_mbps", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_topology_cloud_links_id", "topology_cloud_links", ["id"])
    op.create_index("ix_topology_cloud_links_cloud_id", "topology_cloud_links", ["cloud_id"])
    op.create_index("ix_topology_cloud_links_asset_id", "topology_cloud_links", ["asset_id"])


def downgrade() -> None:
    op.drop_table("topology_cloud_links")
    op.drop_table("topology_clouds")
