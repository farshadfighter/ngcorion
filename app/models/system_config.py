"""
System Configuration Model

A single generic table backs every System Configuration section (time, snmp,
syslog, sms, smtp): one row per section, the section's validated payload stored
as JSON. Certificates live on disk only (/etc/ngcorion/certs) and have no row.

Storing the sections generically keeps schema churn out of Alembic when a
section grows a field — the payload shape is owned by the Pydantic schemas in
app/modules/system_config/schemas.py, which validate on the way in.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from datetime import datetime

from app.core.database import Base


# Section keys used for the one-row-per-section upsert. Certificate is absent
# on purpose: it has no DB row.
SECTION_TIME = "time"
SECTION_SNMP = "snmp"
SECTION_SYSLOG = "syslog"
SECTION_SMS = "sms"
SECTION_SMTP = "smtp"

CONFIG_SECTIONS = (
    SECTION_TIME,
    SECTION_SNMP,
    SECTION_SYSLOG,
    SECTION_SMS,
    SECTION_SMTP,
)


class SystemConfigSetting(Base):
    __tablename__ = "system_config_settings"

    id = Column(Integer, primary_key=True, index=True)
    section = Column(String(50), unique=True, index=True, nullable=False)
    config_json = Column(JSON, nullable=False, default=dict)
    updated_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
