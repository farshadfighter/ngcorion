"""
Audit Log Model

Tracks all sensitive actions in the system for security and compliance.
This table is append-only - no UPDATE or DELETE operations should exist.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AuditLog(Base):
    """
    Audit trail for sensitive operations
    
    Records who did what, when, and from where.
    This table should never be modified or deleted - only appended to.
    """
    
    __tablename__ = "audit_logs"
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique log entry ID"
    )
    
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="User who performed the action (nullable for anonymous/system actions)"
    )
    
    username = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Username at time of action (preserved even if user deleted)"
    )
    
    action = Column(
        String(100),
        nullable=False,
        index=True,
        comment="Action performed (e.g., 'user.create', 'asset.delete', 'permission.update')"
    )
    
    module = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Module where action occurred (e.g., 'user_management', 'asset_list')"
    )
    
    target_id = Column(
        Integer,
        nullable=True,
        comment="ID of the affected resource (e.g., user_id, asset_id)"
    )
    
    ip_address = Column(
        String(50),
        nullable=True,
        index=True,
        comment="IP address of the requester"
    )
    
    result = Column(
        String(20),
        nullable=False,
        default="success",
        comment="Result of the action: 'success' or 'failed'"
    )
    
    detail = Column(
        Text,
        nullable=True,
        comment="Additional context or error message"
    )
    
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        index=True,
        comment="When the action occurred (UTC, timezone-aware)"
    )
    
    # Relationship
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, user='{self.username}', action='{self.action}', result='{self.result}')>"


# ==========================================
# Helper Functions for Logging
# ==========================================

def log_action(
    db,
    user_id: int = None,
    username: str = None,
    action: str = None,
    module: str = None,
    target_id: int = None,
    ip_address: str = None,
    result: str = "success",
    detail: str = None
):
    """
    Create an audit log entry
    
    Args:
        db: Database session
        user_id: ID of user performing action
        username: Username (stored for history even if user deleted)
        action: Action type (e.g., 'user.create', 'asset.delete')
        module: Module name (e.g., 'user_management', 'asset_list')
        target_id: ID of affected resource
        ip_address: IP address of requester
        result: 'success' or 'failed'
        detail: Additional context
    """
    log_entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        module=module,
        target_id=target_id,
        ip_address=ip_address,
        result=result,
        detail=detail
    )
    
    db.add(log_entry)
    db.commit()
    
    return log_entry


# ==========================================
# Convenience Functions for Common Actions
# ==========================================

def log_user_action(db, current_user, action: str, target_id: int, detail: str = None, ip: str = None):
    """Log user management actions"""
    return log_action(
        db=db,
        user_id=current_user.id if current_user else None,
        username=current_user.username if current_user else "system",
        action=action,
        module="user_management",
        target_id=target_id,
        ip_address=ip,
        detail=detail
    )


def log_asset_action(db, current_user, action: str, target_id: int, detail: str = None, ip: str = None):
    """Log asset-related actions"""
    return log_action(
        db=db,
        user_id=current_user.id if current_user else None,
        username=current_user.username if current_user else "system",
        action=action,
        module="asset_list",
        target_id=target_id,
        ip_address=ip,
        detail=detail
    )


def log_discovery_action(db, current_user, action: str, detail: str = None, ip: str = None):
    """Log auto-discovery actions"""
    return log_action(
        db=db,
        user_id=current_user.id if current_user else None,
        username=current_user.username if current_user else "system",
        action=action,
        module="asset_auto_discovery",
        ip_address=ip,
        detail=detail
    )
