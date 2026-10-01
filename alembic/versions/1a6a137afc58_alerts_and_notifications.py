"""alerts and notifications: rules, alerts, deliveries, webhooks; users.phone

Revision ID: 1a6a137afc58
Revises: 7a3c91e5d204
Create Date: 2026-10-01 10:26:02.516499

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1a6a137afc58'
down_revision: Union[str, Sequence[str], None] = '7a3c91e5d204'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("phone", sa.String(20), nullable=True))

    op.create_table(
        "notification_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("severity", sa.String(10), nullable=False, server_default="warning"),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("asset_scope", sa.String(10), nullable=False, server_default="all"),
        sa.Column("asset_filter", sa.JSON(), nullable=False),
        sa.Column("recipients", sa.JSON(), nullable=False),
        sa.Column("channels", sa.JSON(), nullable=False),
        sa.Column("repeat_minutes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notify_resolved", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("quiet_start", sa.String(5), nullable=True),
        sa.Column("quiet_end", sa.String(5), nullable=True),
        sa.Column("group_minutes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_fired_at", sa.DateTime(), nullable=True),
        sa.Column("last_sent_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_notification_rules_id", "notification_rules", ["id"])
    op.create_index("ix_notification_rules_event_type", "notification_rules", ["event_type"])

    op.create_table(
        "notification_webhooks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_notification_webhooks_id", "notification_webhooks", ["id"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("module", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("fingerprint", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_label", sa.String(255), nullable=True),
        sa.Column("link", sa.String(255), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(15), nullable=False, server_default="active"),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("notified_at", sa.DateTime(), nullable=True),
        sa.Column("last_notified_at", sa.DateTime(), nullable=True),
        sa.Column("reminders_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_notice_pending", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_alerts_id", "alerts", ["id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_module", "alerts", ["module"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])
    op.create_index("ix_alerts_asset_id", "alerts", ["asset_id"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_first_seen_at", "alerts", ["first_seen_at"])
    op.create_index("ix_alerts_resolved_at", "alerts", ["resolved_at"])
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])
    op.create_index("uq_alerts_open_fingerprint", "alerts", ["fingerprint"], unique=True,
                    postgresql_where=sa.text("status <> 'resolved'"))

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_ids", sa.JSON(), nullable=False),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("channel", sa.String(10), nullable=False),
        sa.Column("webhook_id", sa.Integer(), sa.ForeignKey("notification_webhooks.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("recipient", sa.String(255), nullable=True),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("severity", sa.String(10), nullable=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_notification_deliveries_id", "notification_deliveries", ["id"])
    op.create_index("ix_notification_deliveries_channel", "notification_deliveries", ["channel"])
    op.create_index("ix_notification_deliveries_created_at", "notification_deliveries", ["created_at"])
    op.create_index("ix_notification_deliveries_pending", "notification_deliveries", ["status", "next_attempt_at"])

    op.create_table(
        "alert_seen",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("seen_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("alert_seen")
    op.drop_table("notification_deliveries")
    op.drop_table("alerts")
    op.drop_table("notification_webhooks")
    op.drop_table("notification_rules")
    op.drop_column("users", "phone")
