"""
How long device configuration backups are kept (System Configuration section "device_backup").

A scheduled backup stores nothing when the configuration is unchanged, so every stored version is a
real change and is kept. What retention removes, after `retention_days` (default 90): backups that
were identical to the asset's previous one when they were taken (a manual backup of an unchanged
device, for example) - never the latest backup of an asset, the first one, a backup a hardening
action can roll back to, or one a restore used.
"""
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models.backup import DeviceBackup
from app.models.system_config import SystemConfigSetting

SECTION = "device_backup"
DEFAULTS = {"retention_days": 90}
MIN_DAYS, MAX_DAYS = 7, 3650


def get_settings(db: Session) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    stored = (row.config_json or {}) if row else {}
    return {k: int(stored.get(k, v)) for k, v in DEFAULTS.items()}


def save_settings(db: Session, retention_days: int, user_id: Optional[int]) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = {"retention_days": max(MIN_DAYS, min(int(retention_days), MAX_DAYS))}
    row.updated_by = user_id
    db.commit()
    return get_settings(db)


def prune(db: Session, now: Optional[datetime] = None) -> int:
    """Delete the duplicate backups older than the retention period; returns how many."""
    from app.models.backup_restore import BackupRestore
    now = now or datetime.utcnow()
    before = now - timedelta(days=get_settings(db)["retention_days"])
    latest = (db.query(DeviceBackup.asset_id, func.max(DeviceBackup.id).label("id"))
              .group_by(DeviceBackup.asset_id).subquery())
    used = db.query(BackupRestore.backup_id).filter(BackupRestore.backup_id.isnot(None)).union(
        db.query(BackupRestore.pre_restore_backup_id).filter(BackupRestore.pre_restore_backup_id.isnot(None)))
    ids = [r[0] for r in db.query(DeviceBackup.id)
           .filter(DeviceBackup.created_at < before, DeviceBackup.changed.is_(False),
                   DeviceBackup.hardening_action_id.is_(None),
                   ~DeviceBackup.id.in_(db.query(latest.c.id)),
                   ~DeviceBackup.id.in_(used))
           .filter(or_(DeviceBackup.confirmed_at.is_(None), DeviceBackup.confirmed_at < before))]
    if ids:
        # a newer backup that pointed at a pruned one now compares against nothing older
        db.query(DeviceBackup).filter(DeviceBackup.previous_backup_id.in_(ids)) \
            .update({"previous_backup_id": None}, synchronize_session=False)
        db.query(DeviceBackup).filter(DeviceBackup.id.in_(ids)).delete(synchronize_session=False)
    db.commit()
    return len(ids)
