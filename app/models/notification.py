"""
Alerts and notifications.

  NotificationRule      which event raises an alert, how urgent it is, who
                        hears about it and over which channels. One row per
                        rule; several rules may watch the same event type
                        (e.g. "device unreachable" as Critical for the core
                        and as Warning for everything else).
  Alert                 one problem, from the moment it is raised until it is
                        resolved: active -> acknowledged -> resolved. In-app
                        delivery is the alert itself.
  NotificationDelivery  one outgoing message (email, SMS, syslog, webhook) for
                        an alert, with its retry state - the Delivery log.
  NotificationWebhook   a webhook target; its signing secret is encrypted.
  AlertSeen             per user: when they last opened the bell, for the
                        unread count.

The engine that raises and resolves alerts is app/modules/alerts/engine.py.
"""
from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String,
                        Text, text)

from app.core.database import Base

SEVERITIES = ("info", "warning", "critical")
ALERT_ACTIVE = "active"
ALERT_ACKNOWLEDGED = "acknowledged"
ALERT_RESOLVED = "resolved"
ALERT_OPEN_STATUSES = (ALERT_ACTIVE, ALERT_ACKNOWLEDGED)

CHANNEL_EMAIL = "email"
CHANNEL_SMS = "sms"
CHANNEL_SYSLOG = "syslog"
CHANNEL_WEBHOOK = "webhook"
CHANNELS = (CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_SYSLOG, CHANNEL_WEBHOOK)


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(60), nullable=False, index=True)   # app/modules/alerts/events.py
    name = Column(String(150), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    severity = Column(String(10), nullable=False, default="warning")
    # Thresholds for the event type, e.g. {"polls": 3} or {"percent": 90, "minutes": 10}.
    params = Column(JSON, nullable=False, default=dict)

    # Which assets: "all", "matching" (asset_filter.type_ids / zone_ids) or
    # "specific" (asset_filter.asset_ids). Ignored by events without an asset.
    asset_scope = Column(String(10), nullable=False, default="all")
    asset_filter = Column(JSON, nullable=False, default=dict)

    # {"roles": [...], "user_ids": [...], "emails": [...], "phones": [...], "owner": bool}
    # "owner" adds the person behind the event (restore requester, job creator).
    recipients = Column(JSON, nullable=False, default=dict)
    # Outgoing channels besides in-app: ["email", "sms", "syslog", "webhook:<id>"]
    channels = Column(JSON, nullable=False, default=list)

    repeat_minutes = Column(Integer, nullable=False, default=0)    # 0 = no reminders
    notify_resolved = Column(Boolean, nullable=False, default=True)
    quiet_start = Column(String(5), nullable=True)                 # "22:00", SMS only
    quiet_end = Column(String(5), nullable=True)                   # "07:00"
    group_minutes = Column(Integer, nullable=False, default=0)     # 0 = send each alert at once

    builtin = Column(Boolean, nullable=False, default=False)       # seeded; can be turned off, not deleted
    last_fired_at = Column(DateTime, nullable=True)
    last_sent_at = Column(DateTime, nullable=True)                 # for grouping bursts
    updated_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        # One open alert per problem, even with several workers evaluating.
        Index("uq_alerts_open_fingerprint", "fingerprint", unique=True,
              postgresql_where=text("status <> 'resolved'")),
        Index("ix_alerts_status_severity", "status", "severity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(60), nullable=False)
    module = Column(String(20), nullable=False, index=True)        # noc | cve | audit | backup | system
    severity = Column(String(10), nullable=False)
    fingerprint = Column(String(255), nullable=False, index=True)  # "<rule id>:<problem key>"
    title = Column(String(255), nullable=False)
    detail = Column(Text, nullable=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    source_label = Column(String(255), nullable=True)              # "RTR-Branch-03 · 10.23.0.1"
    link = Column(String(255), nullable=True)                      # in-app path to act on it
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    status = Column(String(15), nullable=False, default=ALERT_ACTIVE, index=True)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True, index=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)  # null = recovered by itself

    notified_at = Column(DateTime, nullable=True)                  # first outgoing notice; null = not sent yet
    last_notified_at = Column(DateTime, nullable=True)
    reminders_sent = Column(Integer, nullable=False, default=0)
    resolved_notice_pending = Column(Boolean, nullable=False, default=False)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_notification_deliveries_pending", "status", "next_attempt_at"),)

    id = Column(Integer, primary_key=True, index=True)
    alert_ids = Column(JSON, nullable=False, default=list)         # a grouped message covers several
    rule_id = Column(Integer, ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True)
    channel = Column(String(10), nullable=False, index=True)        # email | sms | syslog | webhook
    webhook_id = Column(Integer, ForeignKey("notification_webhooks.id", ondelete="SET NULL"), nullable=True)
    recipient = Column(String(255), nullable=True)
    kind = Column(String(10), nullable=False)                       # raised | reminder | resolved | test
    severity = Column(String(10), nullable=True)
    subject = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    payload = Column(JSON, nullable=True)                           # structured form for syslog / webhook

    status = Column(String(10), nullable=False, default="pending")  # pending | sent | failed | skipped
    attempts = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    sent_at = Column(DateTime, nullable=True)


class NotificationWebhook(Base):
    __tablename__ = "notification_webhooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    url = Column(String(500), nullable=False)
    secret_encrypted = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    last_success_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    last_error_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AlertSeen(Base):
    __tablename__ = "alert_seen"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
