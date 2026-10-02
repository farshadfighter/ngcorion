"""remediation tracking and risk acceptance

Revision ID: b7d41c2e9a10
Revises: e349a4df1521
Create Date: 2026-10-02 09:00:00.000000

remediation_items / remediation_events / risk_acceptances (see
app/models/remediation.py) and the REMEDIATION permission module.

remediation_items and risk_acceptances point at each other, so the
items -> acceptance foreign key is added after both tables exist.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7d41c2e9a10"
down_revision: Union[str, Sequence[str], None] = "e349a4df1521"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE moduleenum ADD VALUE IF NOT EXISTS 'REMEDIATION'")

    op.create_table(
        "remediation_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(255), nullable=False, unique=True),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("ref", sa.String(100), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True),
        sa.Column("asset_name", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(10), nullable=False, server_default="medium"),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(24), nullable=False, server_default="open"),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("due_at", sa.DateTime(), nullable=True),
        sa.Column("due_custom", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("acceptance_id", sa.Integer(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("closed_reason", sa.String(40), nullable=True),
        sa.Column("reopened", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_remediation_items_source", "remediation_items", ["source"])
    op.create_index("ix_remediation_items_ref", "remediation_items", ["ref"])
    op.create_index("ix_remediation_items_asset_id", "remediation_items", ["asset_id"])
    op.create_index("ix_remediation_items_status", "remediation_items", ["status"])
    op.create_index("ix_remediation_items_owner_id", "remediation_items", ["owner_id"])
    op.create_index("ix_remediation_items_status_due", "remediation_items", ["status", "due_at"])

    op.create_table(
        "risk_acceptances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scope", sa.String(10), nullable=False, server_default="item"),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("ref", sa.String(100), nullable=False),
        sa.Column("item_id", sa.Integer(), sa.ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("compensating_control", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("ended_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_risk_acceptances_ref", "risk_acceptances", ["ref"])
    op.create_index("ix_risk_acceptances_item_id", "risk_acceptances", ["item_id"])
    op.create_index("ix_risk_acceptances_status", "risk_acceptances", ["status"])
    op.create_foreign_key("fk_remediation_items_acceptance", "remediation_items", "risk_acceptances",
                          ["acceptance_id"], ["id"], ondelete="SET NULL")

    op.create_table(
        "remediation_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("item_id", sa.Integer(), sa.ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=False),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("data", sa.JSON(), nullable=True),
    )
    op.create_index("ix_remediation_events_item_id", "remediation_events", ["item_id"])


def downgrade() -> None:
    op.drop_table("remediation_events")
    op.drop_constraint("fk_remediation_items_acceptance", "remediation_items", type_="foreignkey")
    op.drop_table("risk_acceptances")
    op.drop_table("remediation_items")
    # PostgreSQL cannot drop an enum value; REMEDIATION stays in moduleenum
    # (harmless without rows that use it) - same as the other module values.
