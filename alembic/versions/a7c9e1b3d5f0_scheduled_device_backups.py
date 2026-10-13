"""scheduled device backups: change tracking on device_backups, backup group runs

Revision ID: a7c9e1b3d5f0
Revises: f6b8d0a2c4e9
Create Date: 2026-10-12
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7c9e1b3d5f0"
down_revision: Union[str, Sequence[str], None] = "f6b8d0a2c4e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("device_backups", sa.Column("previous_backup_id", sa.Integer(),
                                              sa.ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True))
    op.add_column("device_backups", sa.Column("changed", sa.Boolean(), nullable=True))
    op.add_column("device_backups", sa.Column("added_lines", sa.Integer(), nullable=True))
    op.add_column("device_backups", sa.Column("removed_lines", sa.Integer(), nullable=True))
    op.add_column("device_backups", sa.Column("change_origin", sa.String(12), nullable=True))
    op.add_column("device_backups", sa.Column("change_ref", sa.String(40), nullable=True))
    op.add_column("device_backups", sa.Column("confirmed_at", sa.DateTime(), nullable=True))
    op.add_column("device_backups", sa.Column("group_run_id", sa.Integer(),
                                              sa.ForeignKey("group_runs.id", ondelete="SET NULL"), nullable=True))
    op.create_index("ix_device_backups_asset_created", "device_backups", ["asset_id", "created_at"])

    op.add_column("group_runs", sa.Column("kind", sa.String(10), nullable=False, server_default="audit"))
    op.create_index("ix_group_runs_kind", "group_runs", ["kind"])
    op.add_column("group_run_items", sa.Column("backup_id", sa.Integer(), nullable=True))
    op.add_column("group_run_items", sa.Column("outcome", sa.String(12), nullable=True))


def downgrade() -> None:
    op.drop_column("group_run_items", "outcome")
    op.drop_column("group_run_items", "backup_id")
    op.drop_index("ix_group_runs_kind", table_name="group_runs")
    op.drop_column("group_runs", "kind")
    op.drop_index("ix_device_backups_asset_created", table_name="device_backups")
    for c in ("group_run_id", "confirmed_at", "change_ref", "change_origin", "removed_lines", "added_lines",
              "changed", "previous_backup_id"):
        op.drop_column("device_backups", c)
