"""NOC: devices seen in the ARP and MAC tables of monitored routers and switches

Revision ID: e2a4c6f8b1d3
Revises: d1f3a5c7e9b2
Create Date: 2026-10-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e2a4c6f8b1d3"
down_revision: Union[str, Sequence[str], None] = "d1f3a5c7e9b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noc_network_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("mac", sa.String(17), nullable=False, unique=True),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("other_ips", sa.JSON(), nullable=True),
        sa.Column("vendor", sa.String(160), nullable=True),
        sa.Column("private_mac", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("guess_kind", sa.String(20), nullable=True),
        sa.Column("guess_icon", sa.String(20), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("baseline", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("seen_by_asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("seen_if_index", sa.Integer(), nullable=True),
        sa.Column("seen_port", sa.String(255), nullable=True),
        sa.Column("seen_vlan", sa.Integer(), nullable=True),
        sa.Column("seen_via", sa.String(10), nullable=True),
        sa.Column("matched_asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("state", sa.String(10), nullable=False, server_default="open"),
        sa.Column("ignore_note", sa.String(255), nullable=True),
        sa.Column("ignored_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ignored_at", sa.DateTime(), nullable=True),
    )
    for col in ("ip", "first_seen_at", "last_seen_at", "matched_asset_id", "state"):
        op.create_index(f"ix_noc_network_endpoints_{col}", "noc_network_endpoints", [col])
    op.create_table(
        "noc_discovery_sources",
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("first_read_at", sa.DateTime(), nullable=True),
        sa.Column("last_read_at", sa.DateTime(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("arp_entries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mac_entries", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("noc_discovery_sources")
    for col in ("state", "matched_asset_id", "last_seen_at", "first_seen_at", "ip"):
        op.drop_index(f"ix_noc_network_endpoints_{col}", table_name="noc_network_endpoints")
    op.drop_table("noc_network_endpoints")
