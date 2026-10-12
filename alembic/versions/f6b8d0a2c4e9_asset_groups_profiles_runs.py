"""asset tags and groups, credential profiles, group audit runs; scheduled group audits

Revision ID: f6b8d0a2c4e9
Revises: e5a7c9b1d3f8
Create Date: 2026-10-12
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f6b8d0a2c4e9"
down_revision: Union[str, Sequence[str], None] = "e5a7c9b1d3f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _now():
    return sa.func.now()


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'CREDENTIAL_PROFILES'")

    op.create_table(
        "asset_tags",
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tag", sa.String(64), primary_key=True),
    )
    op.create_index("ix_asset_tags_tag", "asset_tags", ["tag"])

    op.create_table(
        "asset_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("kind", sa.String(10), nullable=False, server_default="dynamic"),
        sa.Column("rules", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=_now()),
    )
    op.create_table(
        "asset_group_members",
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index("ix_asset_group_members_asset_id", "asset_group_members", ["asset_id"])

    op.create_table(
        "credential_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("username", sa.String(256), nullable=False),
        sa.Column("secrets_encrypted", sa.Text(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rotation_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("secrets_changed_at", sa.DateTime(timezone=True), nullable=False, server_default=_now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=_now()),
    )

    op.create_table(
        "group_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("asset_groups.id", ondelete="SET NULL"), nullable=True),
        sa.Column("group_name", sa.String(120), nullable=False),
        sa.Column("technology", sa.String(40), nullable=False),
        sa.Column("audit_profile", sa.String(40), nullable=True),
        sa.Column("credential_profile_id", sa.Integer(),
                  sa.ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True),
        sa.Column("credential_profile_name", sa.String(120), nullable=True),
        sa.Column("concurrency", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("status", sa.String(12), nullable=False, server_default="queued"),
        sa.Column("started_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("started_by_name", sa.String(150), nullable=True),
        sa.Column("scheduled_job_id", sa.Integer(), sa.ForeignKey("scheduled_jobs.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_group_runs_group_id", "group_runs", ["group_id"])
    op.create_index("ix_group_runs_status", "group_runs", ["status"])

    op.create_table(
        "group_run_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("group_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True),
        sa.Column("asset_name", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="queued"),
        sa.Column("reason", sa.String(20), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("session_id", sa.Integer(), nullable=True),
        sa.Column("compliance", sa.Float(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("run_id", "asset_id", name="uq_group_run_item_asset"),
    )
    op.create_index("ix_group_run_items_run_id", "group_run_items", ["run_id"])
    op.create_index("ix_group_run_items_status", "group_run_items", ["status"])

    # Scheduled audits of a whole group with a credential profile (no stored password).
    op.add_column("scheduled_jobs", sa.Column("group_id", sa.Integer(),
                                              sa.ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=True))
    op.add_column("scheduled_jobs", sa.Column("credential_profile_id", sa.Integer(),
                                              sa.ForeignKey("credential_profiles.id", ondelete="RESTRICT"),
                                              nullable=True))
    op.add_column("scheduled_jobs", sa.Column("concurrency", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scheduled_jobs", "concurrency")
    op.drop_column("scheduled_jobs", "credential_profile_id")
    op.drop_column("scheduled_jobs", "group_id")
    op.drop_table("group_run_items")
    op.drop_table("group_runs")
    op.drop_table("credential_profiles")
    op.drop_table("asset_group_members")
    op.drop_table("asset_groups")
    op.drop_table("asset_tags")
