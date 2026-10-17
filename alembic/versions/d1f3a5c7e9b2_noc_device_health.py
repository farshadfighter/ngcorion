"""NOC device health: CPU, memory, disk, temperature, host uptime; reboots

Revision ID: d1f3a5c7e9b2
Revises: c9e1a3b5d7f2
Create Date: 2026-10-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d1f3a5c7e9b2"
down_revision: Union[str, Sequence[str], None] = "c9e1a3b5d7f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_snmp_status", sa.Column("device_uptime_ticks", sa.BigInteger(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("cpu_percent", sa.Float(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("memory_percent", sa.Float(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("memory_total_bytes", sa.BigInteger(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("disk_percent", sa.Float(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("temperature_c", sa.Float(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("health", sa.JSON(), nullable=True))
    op.add_column("asset_snmp_status", sa.Column("last_reboot_at", sa.DateTime(), nullable=True))
    op.create_table(
        "noc_device_reboots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.Column("booted_at", sa.DateTime(), nullable=False),
        sa.Column("previous_uptime_seconds", sa.BigInteger(), nullable=True),
    )
    op.create_index("ix_noc_device_reboots_asset_id", "noc_device_reboots", ["asset_id"])
    op.create_index("ix_noc_device_reboots_detected_at", "noc_device_reboots", ["detected_at"])


def downgrade() -> None:
    op.drop_index("ix_noc_device_reboots_detected_at", table_name="noc_device_reboots")
    op.drop_index("ix_noc_device_reboots_asset_id", table_name="noc_device_reboots")
    op.drop_table("noc_device_reboots")
    for col in ("last_reboot_at", "health", "temperature_c", "disk_percent", "memory_total_bytes",
                "memory_percent", "cpu_percent", "device_uptime_ticks"):
        op.drop_column("asset_snmp_status", col)
