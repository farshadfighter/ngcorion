"""configuration changes reported over syslog: events, back up on change

Revision ID: c9e1a3b5d7f2
Revises: b8d0f2a4c6e1
Create Date: 2026-10-14
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c9e1a3b5d7f2"
down_revision: Union[str, Sequence[str], None] = "b8d0f2a4c6e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "config_change_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("changed_by", sa.String(128), nullable=True),
        sa.Column("changed_from", sa.String(128), nullable=True),
        sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
        sa.Column("group_run_id", sa.Integer(), sa.ForeignKey("group_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("backup_id", sa.Integer(), sa.ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
    )
    for col in ("asset_id", "received_at", "status", "group_run_id", "backup_id"):
        op.create_index(f"ix_config_change_events_{col}", "config_change_events", [col])
    op.add_column("group_runs", sa.Column("trigger", sa.String(10), nullable=True))


def downgrade() -> None:
    op.drop_column("group_runs", "trigger")
    for col in ("asset_id", "received_at", "status", "group_run_id", "backup_id"):
        op.drop_index(f"ix_config_change_events_{col}", table_name="config_change_events")
    op.drop_table("config_change_events")
