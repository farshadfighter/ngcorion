"""
Configuration Drift Models

A DriftRun analyzes one asset's *live* configuration against the most recent
DeviceBackup taken for it (the existing backup table doubles as the drift
baseline - there is no separate baseline model). A DriftResult is recorded
only when the live config actually differs from that baseline.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class DriftRun(Base):
    """One drift-analysis pass, triggered for a single asset."""

    __tablename__ = "drift_runs"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    triggered_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(20), nullable=False, default="running")  # running | completed | failed
    assets_checked = Column(Integer, nullable=False, default=0)
    drift_found_count = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)

    asset = relationship("Asset", foreign_keys=[asset_id])
    results = relationship("DriftResult", back_populates="run", cascade="all, delete-orphan", passive_deletes=True)


class DriftResult(Base):
    """A live-vs-baseline diff found for one asset in a drift run."""

    __tablename__ = "drift_results"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("drift_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_name = Column(String(200), nullable=True)
    technology = Column(String(30), nullable=True)  # cisco | fortinet
    baseline_backup_id = Column(Integer, ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True)
    diff = Column(Text, nullable=False)  # unified diff text
    lines_changed = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="low")  # low | medium | high

    status = Column(String(20), nullable=False, default="open", index=True)  # open | accepted | ignored
    ignored_reason = Column(Text, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    run = relationship("DriftRun", back_populates="results")
    asset = relationship("Asset", foreign_keys=[asset_id])
    baseline_backup = relationship("DeviceBackup", foreign_keys=[baseline_backup_id])
    resolver = relationship("User", foreign_keys=[resolved_by])
