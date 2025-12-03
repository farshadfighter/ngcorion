# models/audit.py

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.core.database import Base

class DeviceType(str, enum.Enum):
    CISCO = "cisco"
    LINUX = "linux"
    WINDOWS = "windows"
    FORTINET = "fortinet"

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
    
    checks = relationship("AuditCheck", back_populates="template", cascade="all, delete-orphan")
    sessions = relationship("AuditSession", back_populates="template")

# Individual check items (1.1.1, 1.1.2, ...)
class AuditCheck(Base):
    __tablename__ = "audit_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    template_id = Column(Integer, ForeignKey("audit_templates.id"), nullable=False)
    check_number = Column(String(20), nullable=False)  # "1.1.1"
    title = Column(String(500), nullable=False)
    description = Column(Text)
    command = Column(Text, nullable=False)  # SSH command to run
    expected_output = Column(Text)  # What we're looking for
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    
    template = relationship("AuditTemplate", back_populates="checks")
    results = relationship("AuditResult", back_populates="check")

# Audit execution session
class AuditSession(Base):
    __tablename__ = "audit_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    template_id = Column(Integer, ForeignKey("audit_templates.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id"), nullable=True)  # Optional: link to asset
    
    target_ip = Column(String(50), nullable=False)
    device_type = Column(SQLEnum(DeviceType), nullable=False)
    
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")  # running, completed, failed
    
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    error_checks = Column(Integer, default=0)
    
    template = relationship("AuditTemplate", back_populates="sessions")
    results = relationship("AuditResult", back_populates="session", cascade="all, delete-orphan")

# Results of each check
class AuditResult(Base):
    __tablename__ = "audit_results"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("audit_sessions.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("audit_checks.id"), nullable=False)
    
    status = Column(SQLEnum(CheckStatus), nullable=False)
    actual_output = Column(Text)  # What command returned
    error_message = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow)
    
    session = relationship("AuditSession", back_populates="results")
    check = relationship("AuditCheck", back_populates="results")