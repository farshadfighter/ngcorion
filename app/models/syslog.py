"""
Syslog messages received from the assets (app/modules/syslog).

- SyslogMessage: one message from a registered asset (matched by its IP address), parsed from
  RFC 5424 or the older BSD format (RFC 3164, which Cisco IOS, FortiGate and most Linux systems
  send). Times are naive UTC. Removed after the retention period, or oldest first when the table
  outgrows its storage budget (app/modules/syslog/retention.py).
- SyslogSource: one line per sending address - a registered asset, or an address that is not in the
  inventory (its messages are dropped, only counted) - with first/last seen and counters.
- ConfigChangeEvent: a device reported that its configuration was changed (Cisco %SYS-5-CONFIG_I,
  FortiGate "... configured" events), with who and from where when the message says so. The
  listener backs the device up shortly after (app/modules/syslog/config_changes.py) and links the
  backup, so the change is known within minutes, not at the next nightly backup.
- SyslogStatus: a single row the listener rewrites every few seconds (whether it listens, on which
  port and protocols, the last error), read by the API and the alert on another worker.
"""
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Index, Integer, SmallInteger, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base

# RFC 5424 severities, 0 (most severe) to 7.
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug")


class SyslogMessage(Base):
    __tablename__ = "syslog_messages"

    id = Column(BigInteger, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False)
    received_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    source_ip = Column(String(45), nullable=False)
    protocol = Column(String(3), nullable=False)               # udp | tcp
    facility = Column(SmallInteger, nullable=True)             # 0-23, none when the message had no priority
    severity = Column(SmallInteger, nullable=False, default=5)
    device_time = Column(DateTime, nullable=True)              # the time the device wrote, as sent
    hostname = Column(String(255), nullable=True)
    app_name = Column(String(128), nullable=True)
    message = Column(Text, nullable=False)

    __table_args__ = (
        Index("ix_syslog_messages_asset_received", "asset_id", "received_at"),
        Index("ix_syslog_messages_received", "received_at"),
        Index("ix_syslog_messages_severity_received", "severity", "received_at"),
    )


class SyslogSource(Base):
    __tablename__ = "syslog_sources"

    source_ip = Column(String(45), primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    received = Column(BigInteger, nullable=False, default=0)        # stored messages
    dropped = Column(BigInteger, nullable=False, default=0)         # not in the inventory, over the rate, too long
    last_hostname = Column(String(255), nullable=True)

    asset = relationship("Asset")


class SyslogStatus(Base):
    __tablename__ = "syslog_status"

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, nullable=False, default=False)
    udp = Column(Boolean, nullable=False, default=False)            # listening now
    tcp = Column(Boolean, nullable=False, default=False)
    port = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    queue_dropped = Column(BigInteger, nullable=False, default=0)   # lost because the database could not keep up


class ConfigChangeEvent(Base):
    __tablename__ = "config_change_events"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    received_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    message = Column(Text, nullable=False)
    changed_by = Column(String(128), nullable=True)            # the account the device names
    changed_from = Column(String(128), nullable=True)          # address or line ("10.20.0.15", "console")
    # pending -> queued (a backup run started) -> done | unchanged | failed; no_schedule when no backup
    # schedule covers the device; off when backing up on change is turned off
    status = Column(String(12), nullable=False, default="pending", index=True)
    group_run_id = Column(Integer, ForeignKey("group_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    backup_id = Column(Integer, ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True, index=True)
    processed_at = Column(DateTime, nullable=True)
