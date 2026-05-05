from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
    Enum as SQLEnum,
    Float,
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.core.database import Base


class DeviceType(str, enum.Enum):
    CISCO = "cisco"
    LINUX = "linux"
    WINDOWS = "windows"
    FORTINET = "fortinet"
    APACHE = "apache"
    MONGODB = "mongodb"
    MSSQL = "mssql"


class CheckStatus(str, enum.Enum):
    PASS = "pass"  # Yes
    FAIL = "fail"  # No
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"  # Connection/Command error


# Template for check categories (CIS sections)
class AuditTemplate(Base):
    __tablename__ = "audit_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)  # "CIS Cisco IOS Benchmark v4.1.1"
    device_type = Column(SQLEnum(DeviceType), nullable=False)
    version = Column(String(50))
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)  # NEW: Enable/disable templates
    profile = Column(String(20), default="L1")  # NEW: L1, L2, FULL

    checks = relationship(
        "AuditCheck", back_populates="template", cascade="all, delete-orphan"
    )
    sessions = relationship("AuditSession", back_populates="template")


# Individual check items (1.1.1, 1.1.2, ...)
class AuditCheck(Base):
    __tablename__ = "audit_checks"

    id = Column(Integer, primary_key=True, index=True)
    template_id = Column(Integer, ForeignKey("audit_templates.id"), nullable=False)
    check_number = Column(String(20), nullable=False)  # "IOS-L1-001"
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")  # high, medium, low, info
    level = Column(String(10), default="L1")  # NEW: L1, L2, INFO
    rationale = Column(Text, nullable=True)  # NEW: Why this check matters
    remediation = Column(Text, nullable=True)  # NEW: How to fix if failed

    template = relationship("AuditTemplate", back_populates="checks")
    results = relationship("AuditResult", back_populates="check")


# Audit execution session
class AuditSession(Base):
    __tablename__ = "audit_sessions"

    id = Column(Integer, primary_key=True, index=True)
    template_id = Column(
        Integer, ForeignKey("audit_templates.id"), nullable=True
    )  # Can be null for direct CIS scans
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    asset_id = Column(
        Integer, ForeignKey("asset_inventory.id", ondelete='SET NULL'), nullable=True
    )

    target_ip = Column(String(50), nullable=False)
    device_type = Column(SQLEnum(DeviceType), nullable=False)
    job_name = Column(String(200), nullable=True, comment="User-friendly job name for the audit")

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")  # running, completed, failed

    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    error_checks = Column(Integer, default=0)

    # NEW: Compliance metrics
    compliance_pct = Column(Float, nullable=True)  # Simple percentage
    weighted_compliance_pct = Column(Float, nullable=True)  # Weighted by severity

    # NEW: Error handling
    connection_error = Column(Text, nullable=True)  # SSH connection errors

    # NEW: Raw SSH output (for evidence)
    turbo_dump = Column(Text, nullable=True)  # Full command outputs

    template = relationship("AuditTemplate", back_populates="sessions")
    results = relationship(
        "AuditResult", back_populates="session", cascade="all, delete-orphan"
    )


# Results of each check
class AuditResult(Base):
    __tablename__ = "audit_results"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("audit_sessions.id"), nullable=False)
    check_id = Column(
        Integer, ForeignKey("audit_checks.id"), nullable=True
    )  # Nullable for runtime checks

    # Check details (stored here for runtime CIS checks without check_id)
    check_number = Column(String(20), nullable=True)  # "IOS-L1-001"
    check_title = Column(String(500), nullable=True)
    severity = Column(String(20), nullable=True)
    level = Column(String(10), nullable=True)

    status = Column(SQLEnum(CheckStatus), nullable=False)
    evidence_snippet = Column(Text, nullable=True)  # NEW: Redacted evidence excerpt
    checked_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("AuditSession", back_populates="results")
    check = relationship("AuditCheck", back_populates="results")
