"""Audit: organisation policy on the benchmarks (optional / excluded checks)

Revision ID: a4c6e8f0b2d5
Revises: f3b5d7e9a1c4
Create Date: 2026-10-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a4c6e8f0b2d5"
down_revision: Union[str, Sequence[str], None] = "f3b5d7e9a1c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_policy_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("benchmark", sa.String(40), nullable=False),
        sa.Column("check_number", sa.String(50), nullable=True),
        sa.Column("level", sa.String(10), nullable=True),
        sa.Column("check_title", sa.String(500), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("decision", sa.String(10), nullable=False),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("ended_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_audit_policy_rules_benchmark", "audit_policy_rules", ["benchmark"])
    op.create_index("ix_audit_policy_rules_status", "audit_policy_rules", ["status"])

    op.add_column("audit_sessions", sa.Column("raw_compliance_pct", sa.Float(), nullable=True))
    op.add_column("audit_sessions", sa.Column("raw_weighted_compliance_pct", sa.Float(), nullable=True))
    op.add_column("audit_sessions", sa.Column("policy_optional", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("audit_sessions", sa.Column("policy_excluded", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("audit_sessions", sa.Column("policy_checked_at", sa.DateTime(), nullable=True))
    op.create_index("ix_audit_sessions_policy_checked_at", "audit_sessions", ["policy_checked_at"])
    op.add_column("audit_results", sa.Column("policy", sa.String(10), nullable=True))


def downgrade() -> None:
    # Put back the modules' own scores where the policy had changed them.
    op.execute("UPDATE audit_sessions SET compliance_pct = raw_compliance_pct, "
               "weighted_compliance_pct = raw_weighted_compliance_pct WHERE raw_compliance_pct IS NOT NULL")
    op.drop_column("audit_results", "policy")
    op.drop_index("ix_audit_sessions_policy_checked_at", table_name="audit_sessions")
    for col in ("policy_checked_at", "policy_excluded", "policy_optional", "raw_weighted_compliance_pct",
                "raw_compliance_pct"):
        op.drop_column("audit_sessions", col)
    op.drop_index("ix_audit_policy_rules_status", table_name="audit_policy_rules")
    op.drop_index("ix_audit_policy_rules_benchmark", table_name="audit_policy_rules")
    op.drop_table("audit_policy_rules")
