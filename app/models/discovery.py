"""
Discovery Models

Persistent storage for network scans, discovery applications, and audit trails.
Replaces the in-memory storage pattern with proper database persistence.

Enhanced to support:
- IP ranges and CIDR notation
- Port and protocol configuration
- Pending approval workflow for discovered hosts
- Detailed host information storage
"""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime


class DiscoveryScan(Base):
    """
    Store scan history persistently

    Replaces the in-memory _scans dict in service.py.
    Ensures scans persist across server restarts and provides
    proper audit trail for compliance.

    """
    __tablename__ = "discovery_scans"

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Scan Identification
    scan_id = Column(
        String(50),
        unique=True,
        index=True,
        nullable=False,
        comment="Unique 8-character scan identifier"
    )

    # User Reference
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User who initiated the scan"
    )

    # Scan Parameters
    target = Column(
        String(255),
        nullable=False,
        index=True,
        comment="Target IP, CIDR range, or IP range"
    )

    scan_type = Column(
        String(20),
        nullable=False,
        comment="Scan intensity: basic, detailed, full"
    )

    # Scan Status and Results
    status = Column(
        String(20),
        default="running",
        index=True,
        comment="Scan status: running, completed, failed"
    )

    started_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
        comment="Scan start timestamp"
    )

    completed_at = Column(
        DateTime,
        nullable=True,
        comment="Scan completion timestamp"
    )

    hosts_discovered = Column(
        Integer,
        default=0,
        comment="Total number of hosts found in scan"
    )

    hosts_up = Column(
        Integer,
        default=0,
        comment="Number of live/responsive hosts"
    )

    # Error Tracking
    error_message = Column(
        Text,
        nullable=True,
        comment="Error details if scan failed"
    )

    # Store Full Results as JSON
    results_json = Column(
        JSON,
        nullable=True,
        comment="Complete scan results with discovered hosts"
    )

    # Metadata
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        comment="Record creation timestamp"
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Last update timestamp"
    )

    # Relationships
    user = relationship("User", backref="discovery_scans")
    applications = relationship(
        "DiscoveryApplication",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<DiscoveryScan(scan_id='{self.scan_id}', target='{self.target}', status='{self.status}')>"


class DiscoveryApplication(Base):
    """
    Track when scan results are applied to assets

    Provides audit trail of which discovered data was applied
    to which assets, by whom, and when. Critical for compliance
    and change tracking.

    Attributes:
        id: Primary key
        scan_id: Reference to the scan that provided the data
        asset_id: Which asset was updated
        applied_by_user_id: Who applied the changes
        ip_address: The discovered IP address
        fields_applied: JSON of what fields were updated
        applied_at: When the application occurred
    """
    __tablename__ = "discovery_applications"

    # Primary Key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign Keys
    scan_id = Column(
        String(50),
        ForeignKey("discovery_scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Scan that provided the discovered data"
    )

    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Asset that was updated"
    )

    applied_by_user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who applied the discovery"
    )

    # Application Details
    ip_address = Column(
        String(50),
        comment="Discovered IP address that was applied"
    )

    fields_applied = Column(
        JSON,
        comment="Fields that were updated with discovered values"
    )

    applied_at = Column(
        DateTime,
        default=datetime.utcnow,
        index=True,
        comment="When discovery was applied"
    )

    # Relationships
    scan = relationship("DiscoveryScan", back_populates="applications")
    asset = relationship("Asset", backref="discovery_applications")
    applied_by = relationship("User", backref="applied_discoveries")

    def __repr__(self):
        return f"<DiscoveryApplication(scan_id='{self.scan_id}', asset_id={self.asset_id})>"


class DiscoveryAuditLog(Base):
    """
    Comprehensive audit trail for all discovery operations

    Logs every discovery-related action for security auditing,
    compliance, and debugging. Tracks scans, applications, errors,
    and other significant events.

    Attributes:
        id: Primary key
        user_id: Who performed the action
        action: Type of action (scan_started, discovery_applied, etc.)
        scan_id: Related scan (if applicable)
        asset_id: Related asset (if applicable)
        ip_address: Related IP address
        target: Scan target
        details: Additional context as JSON
        status: Success, failed, or warning
        error_message: Error details if failed
        timestamp: When the action occurred
    """
    __tablename__ = "discovery_audit_logs"

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
        String(50),
        nullable=False,
        index=True,
        comment="Action type: scan_started, scan_completed, discovery_applied, etc."
    )

    # Related Entities
    scan_id = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Related scan ID"
    )

    asset_id = Column(
        Integer,
        nullable=True,
        index=True,
        comment="Related asset ID"
    )

    # Contextual Information
    ip_address = Column(
        String(50),
        nullable=True,
        comment="Related IP address"
    )

    target = Column(
        String(255),
        nullable=True,
        comment="Scan target"
    )

    # Additional Context
    details = Column(
        JSON,
        nullable=True,
        comment="Additional context as JSON"
    )

    # Status and Error Tracking
    status = Column(
        String(20),
        default="success",
        comment="Action status: success, failed, warning"
    )

    error_message = Column(
        Text,
        nullable=True,
        comment="Error message if failed"
    )

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        index=True,
        comment="When the action occurred"
    )

    # Relationships
    user = relationship("User", backref="discovery_audit_logs")

    def __repr__(self):
        return f"<DiscoveryAuditLog(action='{self.action}', user_id={self.user_id}, status='{self.status}')>"


# Helper Functions for Audit Logging

def log_scan_started(db, user_id: int, scan_id: str, target: str, scan_type: str):
    """Helper to log scan start event"""
    log = DiscoveryAuditLog(
        user_id=user_id,
        action="scan_started",
        scan_id=scan_id,
        target=target,
        details={"scan_type": scan_type},
        status="success"
    )
    db.add(log)
    db.commit()


def log_scan_completed(db, user_id: int, scan_id: str, hosts_up: int, hosts_total: int):
    """Helper to log scan completion"""
    log = DiscoveryAuditLog(
        user_id=user_id,
        action="scan_completed",
        scan_id=scan_id,
        details={"hosts_up": hosts_up, "hosts_total": hosts_total},
        status="success"
    )
    db.add(log)
    db.commit()


def log_scan_failed(db, user_id: int, scan_id: str, error: str):
    """Helper to log scan failure"""
    log = DiscoveryAuditLog(
        user_id=user_id,
        action="scan_failed",
        scan_id=scan_id,
        error_message=error,
        status="failed"
    )
    db.add(log)
    db.commit()


def log_discovery_applied(db, user_id: int, scan_id: str, asset_id: int,
                         ip_address: str, fields_applied: dict):
    """Helper to log discovery application"""
    log = DiscoveryAuditLog(
        user_id=user_id,
        action="discovery_applied",
        scan_id=scan_id,
        asset_id=asset_id,
        ip_address=ip_address,
        details={"fields_applied": list(fields_applied.keys())},
        status="success"
    )
    db.add(log)
    db.commit()


def log_asset_created(db, user_id: int, scan_id: str, asset_id: int, ip_address: str):
    """Helper to log asset creation from discovery"""
    log = DiscoveryAuditLog(
        user_id=user_id,
        action="asset_created_from_discovery",
        scan_id=scan_id,
        asset_id=asset_id,
        ip_address=ip_address,
        status="success"
    )
    db.add(log)
    db.commit()
