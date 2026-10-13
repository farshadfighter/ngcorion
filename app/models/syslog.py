"""
Syslog messages received from the assets (app/modules/syslog).

- SyslogMessage: one message from a registered asset (matched by its IP address), parsed from
  RFC 5424 or the older BSD format (RFC 3164, which Cisco IOS, FortiGate and most Linux systems
  send). Times are naive UTC. Removed after the retention period, or oldest first when the table
  outgrows its storage budget (app/modules/syslog/retention.py).
- SyslogSource: one line per sending address - a registered asset, or an address that is not in the
  inventory (its messages are dropped, only counted) - with first/last seen and counters.
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
