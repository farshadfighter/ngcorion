"""
Asset Requirement Audit Log Model

Logs all mutations to asset requirements (asset types, owners, locations,
zones, OS catalog, vendors) for compliance and audit purposes.
"""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime


class AssetRequirementLog(Base):
    """
    Audit trail for asset requirement operations.

    Logs:
    - Excel imports (create/update of asset types, owners, locations, zones, OS catalog, vendors)
    - Individual CRUD operations on requirement entities

    Attributes:
        id: Primary key
        user_id: Who performed the action
        action: Type of action (create, update, delete, excel_import)
        entity_type: Entity type (asset_type, owner, location, zone, os_catalog, vendor)
        entity_id: Related entity ID
        entity_name: Entity name for readability
        details: Additional context as JSON
        status: Success, failed, or partial
        error_message: Error details if failed
        timestamp: When the action occurred
    """
    __tablename__ = "asset_requirement_logs"

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

    entity_type = Column(
        String(64),
        nullable=False,
        index=True,
        comment="Entity type: asset_type, owner, location, zone, os_catalog, vendor"
    )

    # Related Entity
    entity_id = Column(
        Integer,
        nullable=True,
        index=True,
        comment="ID of the affected entity"
    )

    entity_name = Column(
        String(256),
        nullable=True,
        comment="Name of the affected entity for readability"
    )

    # Additional Context
    details = Column(
        JSON,
        nullable=True,
        comment="Additional context (import counts, field changes, etc.)"
    )

    # Status and Error Tracking
    status = Column(
        String(32),
        default="success",
        comment="Status: success, failed, partial"
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
    user = relationship("User", backref="asset_requirement_logs")

    def __repr__(self):
        return f"<AssetRequirementLog(action='{self.action}', entity_type='{self.entity_type}', status='{self.status}')>"


# Helper Functions for Audit Logging

def log_requirement_import(db, user_id: int, results: dict):
    """Log Excel import of asset requirements"""
    log = AssetRequirementLog(
        user_id=user_id,
        action="excel_import",
        entity_type="multiple",
        details={
            "summary": {
                entity: {
                    "created": r.get("created", 0),
                    "updated": r.get("updated", 0),
                    "skipped": r.get("skipped", 0),
                    "errors": len(r.get("errors", []))
                }
                for entity, r in results.items()
            }
        },
        status="success" if all(len(r.get("errors", [])) == 0 for r in results.values()) else "partial"
    )
    db.add(log)
    db.commit()


def log_requirement_create(db, user_id: int, entity_type: str, entity_id: int, entity_name: str):
    """Log creation of a requirement entity"""
    log = AssetRequirementLog(
        user_id=user_id,
        action="create",
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=entity_name,
        status="success"
    )
    db.add(log)
    db.commit()


def log_requirement_update(db, user_id: int, entity_type: str, entity_id: int, entity_name: str, changes: dict = None):
    """Log update of a requirement entity"""
    log = AssetRequirementLog(
        user_id=user_id,
        action="update",
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=entity_name,
        details={"changes": list(changes.keys()) if changes else None},
        status="success"
    )
    db.add(log)
    db.commit()


def log_requirement_delete(db, user_id: int, entity_type: str, entity_id: int, entity_name: str):
    """Log deletion of a requirement entity"""
    log = AssetRequirementLog(
        user_id=user_id,
        action="delete",
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=entity_name,
        status="success"
    )
    db.add(log)
    db.commit()
