"""
Hardening Module Database Models

Tracks all hardening actions (preview and execute operations) for device remediation.
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, backref
from datetime import datetime
from app.core.database import Base


class HardeningAction(Base):
    """
    Tracks all hardening actions (preview and execute).

    Provides complete audit trail of:
    - What commands were run
    - Who ran them
    - When they were run
    - What the results were
    - Whether verification passed
    """
    __tablename__ = "hardening_actions"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Relationships
    audit_result_id = Column(Integer, ForeignKey("audit_results.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id",ondelete="CASCADE"), nullable=False, index=True , comment="Related asset id")
    audit_session_id = Column(Integer, ForeignKey("audit_sessions.id", ondelete="CASCADE"), nullable=False, index=True)

    # Action metadata
    check_number = Column(String(50), nullable=False, index=True)  # e.g., "LNX-RHEL-L1-5.3.1.1"
    check_title = Column(String(500), nullable=False)
    action_type = Column(String(30), nullable=False)  # "preview", "execute" or "manual-execute"
    status = Column(String(30), nullable=False, index=True)  # "pending", "executing", "success", "failed", "blocked"

    # Command details
    commands_json = Column(Text, nullable=False)  # JSON array of commands
    requires_config_mode = Column(Boolean, default=False)

    # Execution details (NULL for preview)
    output = Column(Text, nullable=True)  # Device output from execution
    backup_config = Column(Text, nullable=True)  # Running config before changes
    verification_passed = Column(Boolean, nullable=True)  # Did check pass after fix?
    verification_evidence = Column(Text, nullable=True)  # Evidence from post-fix check

    # FortiGate: which VDOM context the fix was applied in
    # ("global"/"root"/<vdom name>); NULL for flat devices and other device types.
    target_vdom = Column(String(80), nullable=True)

    # Error tracking
    error_message = Column(Text, nullable=True)

    # Credentials tracking (boolean only - never store actual credentials)
    credentials_provided = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    executed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    audit_result = relationship("AuditResult", backref=backref("hardening_actions", passive_deletes=True))
    user = relationship("User", backref="hardening_actions")
    #asset = relationship("Asset", backref="hardening_actions")
    asset = relationship(
    "Asset",
    backref=backref("hardening_actions", cascade="all, delete-orphan"))
    audit_session = relationship("AuditSession", backref=backref("hardening_actions", passive_deletes=True))
    