"""
Deployment Job Model

Safely pushes an already-generated ConfigurationObject to its device through
a precheck -> backup -> apply -> verify pipeline, reusing the same per-tech
hardening executors (and the existing DeviceBackup table) as Configuration's
own direct-apply path - this just wraps that call with a pre-flight
reachability check, a pre-change backup, and a post-change reachability
check, and keeps the outcome of each step for the job's history.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class DeploymentJob(Base):
    """One precheck -> backup -> apply -> verify run against a real device."""

    __tablename__ = "deployment_jobs"

    id = Column(Integer, primary_key=True, index=True)
    configuration_object_id = Column(
        Integer, ForeignKey("configuration_objects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_name = Column(String(200), nullable=True)
    device_type = Column(String(30), nullable=True)

    # queued -> precheck -> (precheck_failed | backup) -> (backup_failed | applying)
    #        -> (apply_failed | verifying) -> (verify_failed | success)
    # rolled_back / rollback_failed reachable only via the explicit rollback action.
    status = Column(String(20), nullable=False, default="queued", index=True)

    precheck_output = Column(Text, nullable=True)
    backup_id = Column(Integer, ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True)
    apply_output = Column(Text, nullable=True)
    verify_output = Column(Text, nullable=True)
    rollback_output = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    configuration_object = relationship("ConfigurationObject")
    asset = relationship("Asset", foreign_keys=[asset_id])
    backup = relationship("DeviceBackup", foreign_keys=[backup_id])
