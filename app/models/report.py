"""
Reports: built documents (PDF / Excel) and the schedules that build them.

Report        one build of a report template with its parameters - who asked,
              for which period and assets, which sections, in which language.
              Its files are kept in ReportFile so the archive list never loads
              the bytes.
ReportFile    the PDF or Excel bytes with their SHA-256, so a file handed
              around later can be checked against the archive.
ReportSchedule  builds a report every day / week / month / quarter and emails
              it. It runs with the permissions of its owner at run time.
"""
from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, LargeBinary, String,
                        Text)

from app.core.database import Base

# Report.status
REPORT_QUEUED = "queued"
REPORT_RUNNING = "running"
REPORT_READY = "ready"
REPORT_FAILED = "failed"
REPORT_CANCELLED = "cancelled"
REPORT_PENDING = (REPORT_QUEUED, REPORT_RUNNING)

# Classification printed on every page
CLASSIFICATIONS = ("public", "internal", "confidential")

FORMATS = ("pdf", "xlsx")
LANGUAGES = ("fa", "en")

# ReportSchedule.frequency
FREQUENCIES = ("daily", "weekly", "monthly", "quarterly")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    code = Column(String(40), nullable=True, unique=True)          # RPT-1405-0142
    template = Column(String(40), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    language = Column(String(5), nullable=False, default="fa")
    formats = Column(JSON, nullable=False, default=list)            # ["pdf", "xlsx"]
    classification = Column(String(20), nullable=False, default="internal")
    params = Column(JSON, nullable=False, default=dict)             # period, scope, sections, options
    period_start = Column(DateTime, nullable=True)                  # resolved, UTC
    period_end = Column(DateTime, nullable=True)
    status = Column(String(12), nullable=False, default=REPORT_QUEUED, index=True)
    progress = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    omitted = Column(JSON, nullable=True)                            # sections left out, and why
    page_count = Column(Integer, nullable=True)
    pinned = Column(Boolean, nullable=False, default=False)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    schedule_id = Column(Integer, ForeignKey("report_schedules.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    # scheduled reports: who received the email, or why it was not sent
    delivered_to = Column(JSON, nullable=True)
    delivery_error = Column(Text, nullable=True)


class ReportFile(Base):
    __tablename__ = "report_files"

    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(8), nullable=False)                         # pdf | xlsx
    filename = Column(String(255), nullable=False)
    size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    content = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    template = Column(String(40), nullable=False)
    title = Column(String(200), nullable=False)
    language = Column(String(5), nullable=False, default="fa")
    formats = Column(JSON, nullable=False, default=list)
    classification = Column(String(20), nullable=False, default="internal")
    params = Column(JSON, nullable=False, default=dict)
    frequency = Column(String(12), nullable=False, default="monthly")
    weekday = Column(Integer, nullable=True)        # 0 = Monday ... 6 = Sunday (weekly)
    monthday = Column(Integer, nullable=True)       # 1-28, in the report language's calendar (monthly, quarterly)
    run_time = Column(String(5), nullable=False, default="08:00")   # local time, HH:MM
    recipient_users = Column(JSON, nullable=False, default=list)    # user ids
    recipient_emails = Column(JSON, nullable=False, default=list)   # other addresses
    attach = Column(Boolean, nullable=False, default=True)
    enabled = Column(Boolean, nullable=False, default=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_run_at = Column(DateTime, nullable=True)                    # UTC
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String(12), nullable=True)                  # sent | ready | failed
    last_error = Column(Text, nullable=True)
    last_report_id = Column(Integer, nullable=True)

    __table_args__ = (Index("ix_report_schedules_due", "enabled", "next_run_at"),)
