"""
Asset Audit Log Model

Logs all mutations to assets (create, update, delete, Excel import)
for compliance and audit purposes.
"""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime


class AssetLog(Base):
    """
    Audit trail for asset operations.

    Logs:
    - Asset creation
    - Asset updates
    - Asset deletion
    - Excel imports

    Attributes:
        id: Primary key
        user_id: Who performed the action
        action: Type of action (create, update, delete, excel_import)
        asset_id: Related asset ID
        asset_name: Asset name for readability
        ip_address: Asset IP address
        details: Additional context as JSON
        status: Success or failed
        error_message: Error details if failed
        timestamp: When the action occurred
    """
    __tablename__ = "asset_logs"

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
        comment="Action type: create, update, delete, excel_import"
    )

    # Related Asset
    asset_id = Column(
        Integer,
        nullable=True,
        index=True,
        comment="ID of the affected asset"
    )

    asset_name = Column(
        String(256),
        nullable=True,
        comment="Name of the affected asset for readability"
    )

    ip_address = Column(
        String(64),
        nullable=True,
        index=True,
        comment="IP address of the asset"
    )

    # Additional Context
    details = Column(
        JSON,
        nullable=True,
        comment="Additional context (field changes, import counts, etc.)"
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
    user = relationship("User", backref="asset_logs")

    def __repr__(self):
        return f"<AssetLog(action='{self.action}', asset_id={self.asset_id}, status='{self.status}')>"


# Helper Functions for Audit Logging

def log_asset_created(db, user_id: int, asset_id: int, asset_name: str, ip_address: str = None):
    """Log asset creation"""
    log = AssetLog(
        user_id=user_id,
        action="create",
        asset_id=asset_id,
        asset_name=asset_name,
        ip_address=ip_address,
        status="success"
    )
    db.add(log)
    db.commit()


def log_asset_updated(db, user_id: int, asset_id: int, asset_name: str, changes: dict = None, ip_address: str = None):
    """Log asset update"""
    log = AssetLog(
        user_id=user_id,
        action="update",
        asset_id=asset_id,
        asset_name=asset_name,
        ip_address=ip_address,
        details={"changes": list(changes.keys()) if changes else None},
        status="success"
    )
    db.add(log)
    db.commit()


def log_asset_deleted(db, user_id: int, asset_id: int, asset_name: str, ip_address: str = None):
    """Log asset deletion"""
    log = AssetLog(
        user_id=user_id,
        action="delete",
        asset_id=asset_id,
        asset_name=asset_name,
        ip_address=ip_address,
        status="success"
    )
    db.add(log)
    db.commit()


def log_asset_import(db, user_id: int, created: int, updated: int, skipped: int, errors: list = None):
    """Log Excel import of assets"""
    log = AssetLog(
        user_id=user_id,
        action="excel_import",
        details={
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "error_count": len(errors) if errors else 0
        },
        status="success" if not errors or len(errors) == 0 else "partial",
        error_message="; ".join(errors[:10]) if errors else None  # Limit error messages
    )
    db.add(log)
    db.commit()
