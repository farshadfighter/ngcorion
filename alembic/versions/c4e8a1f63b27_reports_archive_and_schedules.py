"""reports: archive, files and schedules

Revision ID: c4e8a1f63b27
Revises: b7d41c2e9a10
Create Date: 2026-10-03 09:00:00.000000

reports / report_files / report_schedules (see app/models/report.py) and the
REPORTS permission module. reports.schedule_id points at report_schedules,
so the schedules table is created first.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c4e8a1f63b27"
down_revision: Union[str, Sequence[str], None] = "b7d41c2e9a10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'REPORTS'")

    op.create_table(
        "report_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("template", sa.String(40), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("language", sa.String(5), nullable=False, server_default="fa"),
        sa.Column("formats", sa.JSON(), nullable=False),
        sa.Column("classification", sa.String(20), nullable=False, server_default="internal"),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("frequency", sa.String(12), nullable=False, server_default="monthly"),
        sa.Column("weekday", sa.Integer(), nullable=True),
        sa.Column("monthday", sa.Integer(), nullable=True),
        sa.Column("run_time", sa.String(5), nullable=False, server_default="08:00"),
        sa.Column("recipient_users", sa.JSON(), nullable=False),
        sa.Column("recipient_emails", sa.JSON(), nullable=False),
        sa.Column("attach", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_status", sa.String(12), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_report_id", sa.Integer(), nullable=True),
    )
    op.create_index("ix_report_schedules_owner_id", "report_schedules", ["owner_id"])
    op.create_index("ix_report_schedules_due", "report_schedules", ["enabled", "next_run_at"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(40), nullable=True, unique=True),
        sa.Column("template", sa.String(40), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("language", sa.String(5), nullable=False, server_default="fa"),
        sa.Column("formats", sa.JSON(), nullable=False),
        sa.Column("classification", sa.String(20), nullable=False, server_default="internal"),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("period_start", sa.DateTime(), nullable=True),
        sa.Column("period_end", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(12), nullable=False, server_default="queued"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("omitted", sa.JSON(), nullable=True),
        sa.Column("page_count", sa.Integer(), nullable=True),
        sa.Column("pinned", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("schedule_id", sa.Integer(), sa.ForeignKey("report_schedules.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_to", sa.JSON(), nullable=True),
        sa.Column("delivery_error", sa.Text(), nullable=True),
    )
    op.create_index("ix_reports_template", "reports", ["template"])
    op.create_index("ix_reports_status", "reports", ["status"])
    op.create_index("ix_reports_created_by", "reports", ["created_by"])
    op.create_index("ix_reports_schedule_id", "reports", ["schedule_id"])
    op.create_index("ix_reports_created_at", "reports", ["created_at"])

    op.create_table(
        "report_files",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("report_id", sa.Integer(), sa.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_report_files_report_id", "report_files", ["report_id"])
    op.create_index("ix_report_files_sha256", "report_files", ["sha256"])


def downgrade() -> None:
    op.drop_table("report_files")
    op.drop_table("reports")
    op.drop_table("report_schedules")
    # PostgreSQL cannot drop the 'REPORTS' enum value; it is harmless once the
    # user_permissions rows using it are gone.
