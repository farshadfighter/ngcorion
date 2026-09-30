"""add backup_restores table

Revision ID: b7e2c4a91d30
Revises: 856a4b0ddefc
Create Date: 2026-10-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "b7e2c4a91d30"
down_revision = "856a4b0ddefc"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "backup_restores",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("backup_id", sa.Integer(), sa.ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_name", sa.String(255), nullable=True),
        sa.Column("device_ip", sa.String(50), nullable=True),
        sa.Column("device_type", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("revert_minutes", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("auto_revert", sa.String(20), nullable=False, server_default="unavailable"),
        sa.Column("pre_restore_backup_id", sa.Integer(), sa.ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True),
        sa.Column("diff_summary", sa.JSON(), nullable=True),
        sa.Column("events", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_backup_restores_backup_id", "backup_restores", ["backup_id"])
    op.create_index("ix_backup_restores_asset_id", "backup_restores", ["asset_id"])
    op.create_index("ix_backup_restores_status", "backup_restores", ["status"])
    op.create_index("ix_backup_restores_created_at", "backup_restores", ["created_at"])


def downgrade():
    op.drop_index("ix_backup_restores_created_at", table_name="backup_restores")
    op.drop_index("ix_backup_restores_status", table_name="backup_restores")
    op.drop_index("ix_backup_restores_asset_id", table_name="backup_restores")
    op.drop_index("ix_backup_restores_backup_id", table_name="backup_restores")
    op.drop_table("backup_restores")
