"""syslog intake: messages from registered assets, sending addresses, listener status

Revision ID: b8d0f2a4c6e1
Revises: a7c9e1b3d5f0
Create Date: 2026-10-13
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b8d0f2a4c6e1"
down_revision: Union[str, Sequence[str], None] = "a7c9e1b3d5f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "syslog_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("protocol", sa.String(3), nullable=False),
        sa.Column("facility", sa.SmallInteger(), nullable=True),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("device_time", sa.DateTime(), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("app_name", sa.String(128), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index("ix_syslog_messages_asset_received", "syslog_messages", ["asset_id", "received_at"])
    op.create_index("ix_syslog_messages_received", "syslog_messages", ["received_at"])
    op.create_index("ix_syslog_messages_severity_received", "syslog_messages", ["severity", "received_at"])
    op.create_table(
        "syslog_sources",
        sa.Column("source_ip", sa.String(45), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("received", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("dropped", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_hostname", sa.String(255), nullable=True),
    )
    op.create_index("ix_syslog_sources_asset_id", "syslog_sources", ["asset_id"])
    op.create_index("ix_syslog_sources_last_seen", "syslog_sources", ["last_seen"])
    op.create_table(
        "syslog_status",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("udp", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("tcp", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("queue_dropped", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("syslog_status")
    op.drop_index("ix_syslog_sources_last_seen", table_name="syslog_sources")
    op.drop_index("ix_syslog_sources_asset_id", table_name="syslog_sources")
    op.drop_table("syslog_sources")
    op.drop_index("ix_syslog_messages_severity_received", table_name="syslog_messages")
    op.drop_index("ix_syslog_messages_received", table_name="syslog_messages")
    op.drop_index("ix_syslog_messages_asset_received", table_name="syslog_messages")
    op.drop_table("syslog_messages")
