"""Topology: links found in the LLDP and CDP neighbour tables of monitored devices

Revision ID: f3b5d7e9a1c4
Revises: e2a4c6f8b1d3
Create Date: 2026-10-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f3b5d7e9a1c4"
down_revision: Union[str, Sequence[str], None] = "e2a4c6f8b1d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("topology_links", sa.Column("origin", sa.String(10), nullable=False, server_default="manual"))
    op.add_column("topology_links", sa.Column("last_seen_at", sa.DateTime(), nullable=True))
    op.add_column("topology_links", sa.Column("missing_since", sa.DateTime(), nullable=True))
    for col in ("source_interface", "destination_interface"):
        op.alter_column("topology_links", col, type_=sa.String(100), existing_type=sa.String(50),
                        existing_nullable=True)

    op.create_table(
        "noc_topology_neighbors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("ident", sa.String(40), nullable=False),
        sa.Column("protocol", sa.String(4), nullable=False),
        sa.Column("local_port", sa.String(255), nullable=False),
        sa.Column("local_if_index", sa.Integer(), nullable=True),
        sa.Column("chassis_id", sa.String(255), nullable=True),
        sa.Column("chassis_kind", sa.String(4), nullable=True),
        sa.Column("remote_name", sa.String(255), nullable=True),
        sa.Column("remote_port", sa.String(255), nullable=True),
        sa.Column("remote_port_desc", sa.String(255), nullable=True),
        sa.Column("remote_mgmt_ip", sa.String(45), nullable=True),
        sa.Column("remote_description", sa.String(255), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("matched_asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("link_id", sa.Integer(), sa.ForeignKey("topology_links.id", ondelete="SET NULL"), nullable=True),
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("asset_id", "ident", name="uq_topology_neighbor_ident"),
    )
    for col in ("asset_id", "last_seen_at", "matched_asset_id", "link_id"):
        op.create_index(f"ix_noc_topology_neighbors_{col}", "noc_topology_neighbors", [col])
    op.create_table(
        "noc_topology_sources",
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("last_read_at", sa.DateTime(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("lldp", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cdp", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("neighbors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("chassis_id", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("noc_topology_sources")
    for col in ("link_id", "matched_asset_id", "last_seen_at", "asset_id"):
        op.drop_index(f"ix_noc_topology_neighbors_{col}", table_name="noc_topology_neighbors")
    op.drop_table("noc_topology_neighbors")
    # Found links go with the tables that made them; hand-drawn ones stay.
    op.execute("DELETE FROM topology_links WHERE origin <> 'manual'")
    for col in ("source_interface", "destination_interface"):
        op.execute(f"UPDATE topology_links SET {col} = left({col}, 50)")  # nosec B608 - fixed column names
        op.alter_column("topology_links", col, type_=sa.String(50), existing_type=sa.String(100),
                        existing_nullable=True)
    op.drop_column("topology_links", "missing_since")
    op.drop_column("topology_links", "last_seen_at")
    op.drop_column("topology_links", "origin")
