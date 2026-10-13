"""
Device configuration backups (DeviceBackup): snapshots taken by hand, automatically before a
hardening run or a restore, or by a scheduled backup of an asset group; used by Backup / Restore.

Every new backup is compared with the asset's previous one when it is saved
(app/modules/backup/changes.py): `changed`, the lines added and removed, and where the change came
from - "external" (made outside NGCorion) or "ngcorion" (a hardening or restore NGCorion ran in
between). A scheduled backup that finds the configuration unchanged is not stored again; it marks
the latest copy `confirmed_at` instead.
"""
from sqlalchemy import Boolean, Column, Integer, Index, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship, backref
from datetime import datetime
from app.core.database import Base


class DeviceBackup(Base):
    """Stores device configuration backups taken manually or during hardening."""

    __tablename__ = "device_backups"
    __table_args__ = (Index("ix_device_backups_asset_created", "asset_id", "created_at"),)

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_name = Column(String(255), nullable=True)
    device_ip = Column(String(50), nullable=True)
    device_type = Column(String(30), nullable=True)  # cisco / fortinet
    config_content = Column(Text, nullable=False)
    source = Column(String(20), nullable=False, default="manual")  # manual | hardening | pre_restore | scheduled
    hardening_action_id = Column(
        Integer,
        ForeignKey("hardening_actions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Compared with the previous backup of the asset when saved (app/modules/backup/changes.py).
    previous_backup_id = Column(Integer, ForeignKey("device_backups.id", ondelete="SET NULL"), nullable=True)
    changed = Column(Boolean, nullable=True)                 # None: the first backup of the asset
    added_lines = Column(Integer, nullable=True)
    removed_lines = Column(Integer, nullable=True)
    change_origin = Column(String(12), nullable=True)       # first | unchanged | external | ngcorion
    change_ref = Column(String(40), nullable=True)          # "hardening:<id>" / "restore:<id>"
    # Last time a scheduled backup found the device still configured exactly like this copy.
    confirmed_at = Column(DateTime, nullable=True)
    group_run_id = Column(Integer, ForeignKey("group_runs.id", ondelete="SET NULL"), nullable=True)

    asset = relationship("Asset", backref=backref("device_backups", passive_deletes=True))
    user = relationship("User", backref="device_backups")
