"""SNMP address of a host; other addresses of an asset (syslog)

- asset_snmp_credentials.poll_address: where SNMP reaches the device when that is not its inventory
  address (a management interface); NULL = the asset's IP address.
- asset_addresses: other addresses an asset sends syslog from (a logging interface, HA units); an
  address belongs to one asset.

Revision ID: d9f1b3c5e7a8
Revises: c7e9a1b3d5f6
Create Date: 2026-10-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d9f1b3c5e7a8"
down_revision: Union[str, Sequence[str], None] = "c7e9a1b3d5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_snmp_credentials", sa.Column("poll_address", sa.String(255), nullable=True))
    op.create_table(
        "asset_addresses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("address", sa.String(45), nullable=False, comment="IPv4 or IPv6, normalised"),
        sa.Column("note", sa.String(120), nullable=True, comment="What the address is, e.g. logging interface"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("address", name="uq_asset_addresses_address"),
    )
    op.create_index("ix_asset_addresses_asset_id", "asset_addresses", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_asset_addresses_asset_id", table_name="asset_addresses")
    op.drop_table("asset_addresses")
    op.drop_column("asset_snmp_credentials", "poll_address")
