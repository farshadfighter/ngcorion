"""system backup: archive catalog, destinations, restores

Revision ID: d91f5b7e2a40
Revises: c4e8a1f63b27
Create Date: 2026-10-04 09:00:00.000000

system_backups / backup_destinations / system_restores (see
app/models/system_backup.py). Admin-only, so no permission module.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d91f5b7e2a40"
down_revision: Union[str, Sequence[str], None] = "c4e8a1f63b27"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "system_backups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(12), nullable=False, server_default="manual"),
        sa.Column("tier", sa.String(8), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="queued"),
        sa.Column("step", sa.String(40), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("contents", sa.JSON(), nullable=False),
        sa.Column("filename", sa.String(200), nullable=True, unique=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("app_version", sa.String(20), nullable=True),
        sa.Column("db_revision", sa.String(40), nullable=True),
        sa.Column("key_id", sa.String(40), nullable=True),
        sa.Column("source_host", sa.String(120), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("destinations", sa.JSON(), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("verify_status", sa.String(10), nullable=True),
        sa.Column("verify_error", sa.Text(), nullable=True),
        sa.Column("tested_at", sa.DateTime(), nullable=True),
        sa.Column("test_status", sa.String(10), nullable=True),
        sa.Column("note", sa.String(300), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("runner", sa.String(120), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_by_name", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_system_backups_kind", "system_backups", ["kind"])
    op.create_index("ix_system_backups_status", "system_backups", ["status"])
    op.create_index("ix_system_backups_created_at", "system_backups", ["created_at"])

    op.create_table(
        "backup_destinations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("type", sa.String(8), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("domain", sa.String(120), nullable=True),
        sa.Column("share", sa.String(255), nullable=True),
        sa.Column("path", sa.String(500), nullable=True),
        sa.Column("auth", sa.String(10), nullable=False, server_default="password"),
        sa.Column("secret_encrypted", sa.Text(), nullable=True),
        sa.Column("host_key", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_status", sa.String(10), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "system_restores",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False, server_default="restore"),
        sa.Column("backup_id", sa.Integer(), sa.ForeignKey("system_backups.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("backup_label", sa.String(200), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="queued"),
        sa.Column("step", sa.String(40), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("safety_backup_id", sa.Integer(), sa.ForeignKey("system_backups.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("runner", sa.String(120), nullable=True),
        sa.Column("requested_by", sa.Integer(), nullable=True),
        sa.Column("requested_by_name", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_system_restores_kind", "system_restores", ["kind"])
    op.create_index("ix_system_restores_backup_id", "system_restores", ["backup_id"])
    op.create_index("ix_system_restores_status", "system_restores", ["status"])
    op.create_index("ix_system_restores_created_at", "system_restores", ["created_at"])


def downgrade() -> None:
    op.drop_table("system_restores")
    op.drop_table("backup_destinations")
    op.drop_table("system_backups")
