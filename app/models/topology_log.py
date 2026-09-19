"""
Topology Audit Log Model

Logs all mutations to topology links (create, update, delete) for
compliance and audit purposes. Mirrors app/models/asset_log.py.
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


class TopologyLog(Base):
    """Audit trail for topology link operations."""

    __tablename__ = "topology_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who performed the action",
    )

    action = Column(
        String(64),
        nullable=False,
        index=True,
        comment="Action type: create, update, delete",
    )

    link_id = Column(
        Integer,
        nullable=True,
        index=True,
        comment="ID of the affected topology link",
    )

    details = Column(
        JSON,
        nullable=True,
        comment="Additional context (endpoints, field changes, etc.)",
    )

    status = Column(String(32), default="success", comment="Status: success, failed")

    timestamp = Column(
        DateTime(timezone=True),
        default=_utcnow,
        index=True,
        comment="When the action occurred (UTC, timezone-aware)",
    )

    user = relationship("User", backref="topology_logs")

    def __repr__(self):
        return f"<TopologyLog(action='{self.action}', link_id={self.link_id}, status='{self.status}')>"


def log_topology_link_created(db, user_id: int, link_id: int, source_asset_id: int, destination_asset_id: int):
    log = TopologyLog(
        user_id=user_id,
        action="create",
        link_id=link_id,
        details={"source_asset_id": source_asset_id, "destination_asset_id": destination_asset_id},
        status="success",
    )
    db.add(log)
    db.commit()


def log_topology_link_updated(db, user_id: int, link_id: int, changes: dict = None):
    log = TopologyLog(
        user_id=user_id,
        action="update",
        link_id=link_id,
        details={"changes": list(changes.keys()) if changes else None},
        status="success",
    )
    db.add(log)
    db.commit()


def log_topology_link_deleted(db, user_id: int, link_id: int):
    log = TopologyLog(
        user_id=user_id,
        action="delete",
        link_id=link_id,
        status="success",
    )
    db.add(log)
    db.commit()
