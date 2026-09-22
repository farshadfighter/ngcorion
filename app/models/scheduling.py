"""
Scheduled Jobs - unattended, recurring Auto Discovery scans and per-tech
Audits.

One ScheduledJob row = one recurring job. `params_encrypted` is a JSON blob
of exactly the extra kwargs needed to replay the underlying call later
(DiscoveryService.start_scan's ScanRequest fields for job_type="discovery",
or the matching tech's AuditService.execute_*_audit kwargs - including
credentials - for job_type="audit"). Always encrypted (app/core/
credential_crypto.py), even for discovery, which has no real secret, so
there is one code path rather than two.

ScheduledJobRun is a lightweight run history, one row per firing, so a user
can see that a job actually ran unattended and what happened - not just the
job's own last-run summary fields.
"""
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

# Recognized job_type values.
JOB_TYPE_DISCOVERY = "discovery"
JOB_TYPE_AUDIT = "audit"

# Recognized recurrence values.
RECURRENCE_ONCE = "once"
RECURRENCE_HOURLY = "hourly"
RECURRENCE_DAILY = "daily"
RECURRENCE_WEEKLY = "weekly"


class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_name = Column(String(200), nullable=False)
    job_type = Column(String(20), nullable=False, index=True)  # discovery | audit

    # Audit jobs only - which tech-specific AuditService to dispatch to.
    technology = Column(String(20), nullable=True)  # cisco|fortinet|linux|apache|mongodb|mssql|windows
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    params_encrypted = Column(Text, nullable=False)

    recurrence = Column(String(20), nullable=False, default=RECURRENCE_DAILY)
    hour = Column(Integer, nullable=True)  # 0-23, time of day for daily/weekly
    minute = Column(Integer, nullable=False, default=0)  # 0-59
    day_of_week = Column(Integer, nullable=True)  # 0=Mon..6=Sun, weekly only

    enabled = Column(Boolean, nullable=False, default=True, index=True)
    next_run_at = Column(DateTime, nullable=False, index=True)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(20), nullable=True)  # success | failed
    last_run_message = Column(Text, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset")
    runs = relationship("ScheduledJobRun", back_populates="job", cascade="all, delete-orphan")


class ScheduledJobRun(Base):
    __tablename__ = "scheduled_job_runs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(
        Integer,
        ForeignKey("scheduled_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False, default="running")  # running|success|failed
    message = Column(Text, nullable=True)
    # e.g. "scan:123" or "audit_session:456" - lets the UI link to the real result.
    result_ref = Column(String(100), nullable=True)

    job = relationship("ScheduledJob", back_populates="runs")
