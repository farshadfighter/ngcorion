"""
Configuration Job Models

A ConfigurationJob generates device configuration from a design version's
components (one ConfigurationObject per mapped component) and optionally
pushes it to the real device, reusing the existing per-tech hardening
executors' command-execution methods as the device-I/O layer.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class ConfigurationJob(Base):
    """One configuration-generation run over a design version."""

    __tablename__ = "configuration_jobs"

    id = Column(Integer, primary_key=True, index=True)
    design_version_id = Column(
        Integer, ForeignKey("architecture_design_versions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name = Column(String(200), nullable=False)
    status = Column(String(20), nullable=False, default="generated")  # generated | applied | partially_applied
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    design_version = relationship("ArchitectureDesignVersion")
    objects = relationship(
        "ConfigurationObject", back_populates="job",
        cascade="all, delete-orphan", passive_deletes=True,
    )


class ConfigurationObject(Base):
    """The generated configuration for one component/asset within a job."""

    __tablename__ = "configuration_objects"

    id = Column(Integer, primary_key=True, index=True)
    configuration_job_id = Column(Integer, ForeignKey("configuration_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    design_component_id = Column(Integer, ForeignKey("design_components.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_name = Column(String(200), nullable=True)
    device_type = Column(String(30), nullable=True)  # cisco | fortinet | (unsupported types generate comments only)
    generated_config = Column(Text, nullable=False)

    apply_status = Column(String(20), nullable=False, default="pending")  # pending | success | failed
    apply_output = Column(Text, nullable=True)
    applied_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    applied_at = Column(DateTime, nullable=True)

    job = relationship("ConfigurationJob", back_populates="objects")
    design_component = relationship("DesignComponent")
    asset = relationship("Asset", foreign_keys=[asset_id])
