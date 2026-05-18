"""
Hardening Log Model

Logs all hardening operations (preview, execute, batch, auto-harden) for audit trail.
Separate from HardeningAction which tracks technical execution details.

This provides user-level summary logging for compliance and monitoring.
"""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


class HardeningLog(Base):
    """
    Audit trail for hardening operations.

    Logs:
    - Hardening previews
    - Hardening executions (single and batch)
    - Auto-hardening operations
    - Failures and errors

    Attributes:
        id: Primary key
        user_id: Who performed the action
        action: Type of action (preview, execute, batch_execute, auto_harden)
        asset_id: Related asset ID
        asset_name: Asset name for readability
        audit_session_id: Related audit session (if applicable)
        device_type: Device type (cisco, fortinet, linux, etc.)
        check_ids: List of check IDs involved
        check_count: Number of checks processed
        details: Additional context as JSON
        status: Success, failed, or partial
        success_count: Number of successful operations
        failed_count: Number of failed operations
        error_message: Error details if failed
        timestamp: When the action occurred
    """
    __tablename__ = "hardening_logs"

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
        comment="Action type: preview, execute, batch_execute, auto_harden"
    )

    # Related Asset
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="ID of the affected asset"
    )

    asset_name = Column(
        String(256),
        nullable=True,
        comment="Name of the affected asset for readability"
    )

    # Related Audit Session
    audit_session_id = Column(
        Integer,
        ForeignKey("audit_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Related audit session"
    )

    # Device Type
    device_type = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Device type: cisco, fortinet, linux, apache, windows, mssql, mongodb"
    )

    # Check Details
    check_ids = Column(
        JSON,
        nullable=True,
        comment="List of check IDs involved in this operation"
    )

    check_count = Column(
        Integer,
        default=0,
        comment="Number of checks processed"
    )

    # Additional Context
    details = Column(
        JSON,
        nullable=True,
        comment="Additional context (parameters, warnings, etc.)"
    )

    # Status and Counts
    status = Column(
        String(32),
        default="success",
        index=True,
        comment="Status: success, failed, partial"
    )

    success_count = Column(
        Integer,
        default=0,
        comment="Number of successful operations"
    )

    failed_count = Column(
        Integer,
        default=0,
        comment="Number of failed operations"
    )

    error_message = Column(
        Text,
        nullable=True,
        comment="Error details if failed"
    )

    timestamp = Column(
        DateTime(timezone=True),
        default=_utcnow,
        index=True,
        comment="When the action occurred (UTC, timezone-aware)"
    )

    # Relationships
    user = relationship("User", backref="hardening_logs")
    asset = relationship("Asset", backref="hardening_logs")
    audit_session = relationship("AuditSession", backref="hardening_logs")

    def __repr__(self):
        return f"<HardeningLog(action='{self.action}', asset_id={self.asset_id}, status='{self.status}')>"


# Helper Functions for Hardening Logging

def log_hardening_preview(
    db,
    user_id: int,
    asset_id: int,
    asset_name: str,
    audit_session_id: int,
    device_type: str,
    check_number: str,
    check_title: str,
    status: str = "success",
    error: str = None
):
    """Log hardening preview operation"""
    try:
        log = HardeningLog(
            user_id=user_id,
            action="preview",
            asset_id=asset_id,
            asset_name=asset_name,
            audit_session_id=audit_session_id,
            device_type=device_type,
            check_ids=[check_number],
            check_count=1,
            details={"check_title": check_title},
            status=status,
            success_count=1 if status == "success" else 0,
            failed_count=1 if status == "failed" else 0,
            error_message=error
        )
        db.add(log)
        db.commit()
    except Exception as e:
        # Never let logging break the main operation
        db.rollback()
        print(f"Warning: Failed to log hardening preview: {e}")


def log_hardening_execute(
    db,
    user_id: int,
    asset_id: int,
    asset_name: str,
    audit_session_id: int,
    device_type: str,
    check_number: str,
    check_title: str,
    verification_passed: bool = None,
    status: str = "success",
    error: str = None
):
    """Log hardening execute operation"""
    try:
        log = HardeningLog(
            user_id=user_id,
            action="execute",
            asset_id=asset_id,
            asset_name=asset_name,
            audit_session_id=audit_session_id,
            device_type=device_type,
            check_ids=[check_number],
            check_count=1,
            details={
                "check_title": check_title,
                "verification_passed": verification_passed
            },
            status=status,
            success_count=1 if status == "success" else 0,
            failed_count=1 if status == "failed" else 0,
            error_message=error
        )
        db.add(log)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Warning: Failed to log hardening execute: {e}")


def log_batch_hardening(
    db,
    user_id: int,
    asset_id: int,
    asset_name: str,
    audit_session_id: int,
    device_type: str,
    check_ids: list,
    success_count: int,
    failed_count: int,
    details: dict = None,
    error: str = None
):
    """Log batch hardening operation"""
    try:
        total = success_count + failed_count
        if failed_count == 0:
            status = "success"
        elif success_count == 0:
            status = "failed"
        else:
            status = "partial"

        log = HardeningLog(
            user_id=user_id,
            action="batch_execute",
            asset_id=asset_id,
            asset_name=asset_name,
            audit_session_id=audit_session_id,
            device_type=device_type,
            check_ids=check_ids,
            check_count=total,
            details=details or {},
            status=status,
            success_count=success_count,
            failed_count=failed_count,
            error_message=error
        )
        db.add(log)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Warning: Failed to log batch hardening: {e}")


def log_auto_hardening(
    db,
    user_id: int,
    asset_id: int,
    asset_name: str,
    audit_session_id: int,
    device_type: str,
    check_ids: list,
    success_count: int,
    failed_count: int,
    details: dict = None,
    error: str = None
):
    """Log auto-hardening operation"""
    try:
        total = success_count + failed_count
        if failed_count == 0:
            status = "success"
        elif success_count == 0:
            status = "failed"
        else:
            status = "partial"

        log = HardeningLog(
            user_id=user_id,
            action="auto_harden",
            asset_id=asset_id,
            asset_name=asset_name,
            audit_session_id=audit_session_id,
            device_type=device_type,
            check_ids=check_ids,
            check_count=total,
            details=details or {},
            status=status,
            success_count=success_count,
            failed_count=failed_count,
            error_message=error
        )
        db.add(log)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Warning: Failed to log auto hardening: {e}")
