"""
Audit Module Log Model

Logs all audit session mutations (execute, delete) for compliance purposes.
Note: This is separate from AuditSession/AuditResult which store audit findings.
"""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime


class AuditModuleLog(Base):
    """
    Audit trail for audit module operations.

    Logs:
    - Audit execution (session creation)
    - Audit session deletion

    Attributes:
        id: Primary key
        user_id: Who performed the action
        action: Type of action (execute_audit, delete_session)
        session_id: Related audit session ID
        asset_id: Target asset ID
        asset_name: Target asset name
        target_ip: Target IP address
        audit_type: Audit type (cisco_cis, cis_benchmark)
        profile: CIS profile (L1, FULL)
        details: Additional context as JSON
        status: Success or failed
        error_message: Error details if failed
        timestamp: When the action occurred
    """
    __tablename__ = "audit_module_logs"

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # User Reference
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who performed the action"
    )

    # Action Details
    action = Column(
        String(64),
        nullable=False,
        index=True,
        comment="Action type: execute_audit, delete_session"
    )

    # Related Session
    session_id = Column(
        Integer,
        nullable=True,
        index=True,
        comment="ID of the audit session"
    )

    # Related Asset
    asset_id = Column(
        Integer,
        nullable=True,
        index=True,
        comment="ID of the target asset"
    )

    asset_name = Column(
        String(256),
        nullable=True,
        comment="Name of the target asset"
    )

    target_ip = Column(
        String(64),
        nullable=True,
        comment="Target IP address"
    )

    # Audit Configuration
    audit_type = Column(
        String(64),
        nullable=True,
        comment="Audit type: cisco_cis, cis_benchmark"
    )

    profile = Column(
        String(32),
        nullable=True,
        comment="CIS profile: L1, FULL"
    )

    # Additional Context
    details = Column(
        JSON,
        nullable=True,
        comment="Additional context (compliance results, etc.)"
    )

    # Status and Error Tracking
    status = Column(
        String(32),
        default="success",
        comment="Status: success, failed"
    )

    error_message = Column(
        Text,
        nullable=True,
        comment="Error details if failed"
    )

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        index=True,
        comment="When the action occurred"
    )

    # Relationships
    user = relationship("User", backref="audit_module_logs")

    def __repr__(self):
        return f"<AuditModuleLog(action='{self.action}', session_id={self.session_id}, status='{self.status}')>"


# Helper Functions for Audit Logging

def log_audit_executed(db, user_id: int, session_id: int, asset_id: int = None, asset_name: str = None,
                       target_ip: str = None, audit_type: str = None, profile: str = None,
                       compliance_pct: float = None, status: str = "success", error: str = None):
    """Log audit execution"""
    log = AuditModuleLog(
        user_id=user_id,
        action="execute_audit",
        session_id=session_id,
        asset_id=asset_id,
        asset_name=asset_name,
        target_ip=target_ip,
        audit_type=audit_type,
        profile=profile,
        details={"compliance_pct": compliance_pct} if compliance_pct is not None else None,
        status=status,
        error_message=error
    )
    db.add(log)
    db.commit()


def log_audit_session_deleted(db, user_id: int, session_id: int, asset_id: int = None,
                               asset_name: str = None, target_ip: str = None):
    """Log audit session deletion"""
    log = AuditModuleLog(
        user_id=user_id,
        action="delete_session",
        session_id=session_id,
        asset_id=asset_id,
        asset_name=asset_name,
        target_ip=target_ip,
        status="success"
    )
    db.add(log)
    db.commit()
