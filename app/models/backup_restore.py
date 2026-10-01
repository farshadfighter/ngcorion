"""
A restore of a DeviceBackup onto its device.

One row per attempt. The job runs in the background (see
app/modules/backup/restore/service.py); the wizard polls it for progress. SSH
credentials are held in memory for the duration of the run only and are never
written here.
"""
from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base

# queued -> connecting -> backing_up -> applying -> verifying -> saving -> succeeded
# Any step may end in: reverting -> reverted (device back on its previous
# configuration), or failed (nothing was changed, or the outcome needs a human).
RESTORE_ACTIVE_STATUSES = ("queued", "connecting", "backing_up", "applying", "verifying", "saving", "reverting")
RESTORE_FINAL_STATUSES = ("succeeded", "reverted", "failed")


class BackupRestore(Base):
    __tablename__ = "backup_restores"

    id = Column(Integer, primary_key=True, index=True)
    backup_id = Column(
        Integer, ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id = Column(
        Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_name = Column(String(255), nullable=True)
    device_ip = Column(String(50), nullable=True)
    device_type = Column(String(30), nullable=False)

    status = Column(String(20), nullable=False, default="queued", index=True)
    reason = Column(Text, nullable=False)
    revert_minutes = Column(Integer, nullable=False, default=10)
    auto_revert = Column(String(20), nullable=False, default="unavailable")  # armed | unavailable

    # Undo point: the device's configuration captured right before applying.
    pre_restore_backup_id = Column(
        Integer, ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True
    )
    # {"added": n, "removed": n, "sections": n, "management_risks": [...]}
    diff_summary = Column(JSON, nullable=True)
    # [{"at": iso, "step": "...", "status": "done|running|failed|info", "message": "..."}]
    events = Column(JSON, nullable=False, default=list)
    error = Column(Text, nullable=True)

    requested_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    runner = Column(String(160), nullable=True)         # app/core/singleton.runner_tag()
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    backup = relationship("DeviceBackup", foreign_keys=[backup_id])
    pre_restore_backup = relationship("DeviceBackup", foreign_keys=[pre_restore_backup_id])
    user = relationship("User")
