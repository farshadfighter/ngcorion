"""
Backup & Restore overview: is every device's configuration saved, and what
was restored recently.

"Supported" devices are the assets a backup can be taken from - their family
(inferred from the asset, or the type of a backup already taken) is one of the
restore drivers' families. A device is "fresh" with a backup newer than
`stale_days`, "stale" with an older one, "never" with none.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from app.models import Asset, DeviceBackup, User
from app.models.backup_restore import RESTORE_ACTIVE_STATUSES, BackupRestore
from app.modules.backup.restore.drivers import SUPPORTED_FAMILIES
from app.utils.device_classification import infer_device_family

STALE_DAYS = 30
ATTENTION_LIMIT = 200
FAMILY_LABELS = {"fortinet": "Fortinet", "cisco": "Cisco", "linux": "Linux", "apache": "Apache", "mongodb": "MongoDB"}

# Restore list filters -> statuses.
RESTORE_GROUPS = {
    "active": RESTORE_ACTIVE_STATUSES,
    "succeeded": ("succeeded",),
    "reverted": ("reverted",),
    "failed": ("failed",),
}


def compute_overview(db: Session, now: Optional[datetime] = None, stale_days: int = STALE_DAYS) -> Dict:
    now = now or datetime.utcnow()
    stale_before = now - timedelta(days=stale_days)
    month_ago = now - timedelta(days=30)

    last = {}   # asset_id -> (last backup time, device_type)
    for asset_id, created, device_type in (
        db.query(DeviceBackup.asset_id, DeviceBackup.created_at, DeviceBackup.device_type)
        .order_by(DeviceBackup.asset_id, DeviceBackup.created_at.desc())
        .distinct(DeviceBackup.asset_id)
    ):
        last[asset_id] = (created, (device_type or "").lower())

    devices: List[Dict] = []
    for a in db.query(Asset).options(joinedload(Asset.asset_type)).all():
        when, backup_type = last.get(a.id, (None, None))
        family = infer_device_family(a)
        if family not in SUPPORTED_FAMILIES:
            family = backup_type if backup_type in SUPPORTED_FAMILIES else None
        if family is None:
            continue
        state = "never" if when is None else "stale" if when < stale_before else "fresh"
        devices.append({"asset_id": a.id, "asset_name": a.asset_name, "ip_address": a.ip_address,
                        "icon": a.resolved_icon, "family": family, "last_backup_at": when, "state": state})

    by_family = []
    for family in SUPPORTED_FAMILIES:
        members = [d for d in devices if d["family"] == family]
        if members:
            by_family.append({"family": family, "label": FAMILY_LABELS.get(family, family.title()),
                              "total": len(members), "fresh": sum(1 for d in members if d["state"] == "fresh")})

    attention = sorted((d for d in devices if d["state"] != "fresh"),
                       key=lambda d: (d["state"] != "never", d["last_backup_at"] or now, (d["asset_name"] or "").lower()))

    # Backups in the last 30 days, per source and per day.
    sources = dict(db.query(DeviceBackup.source, func.count(DeviceBackup.id))
                   .filter(DeviceBackup.created_at >= month_ago).group_by(DeviceBackup.source).all())
    day = func.date(DeviceBackup.created_at)
    per_day = {}
    for d, source, n in (db.query(day, DeviceBackup.source, func.count(DeviceBackup.id))
                         .filter(DeviceBackup.created_at >= month_ago).group_by(day, DeviceBackup.source)):
        slot = per_day.setdefault(d.isoformat(), {"manual": 0, "automatic": 0})
        slot["manual" if source == "manual" else "automatic"] += n
    daily = []
    for i in range(29, -1, -1):
        d = (now - timedelta(days=i)).date().isoformat()
        daily.append({"date": d, **per_day.get(d, {"manual": 0, "automatic": 0})})

    restores = dict(db.query(BackupRestore.status, func.count(BackupRestore.id))
                    .filter(BackupRestore.created_at >= month_ago).group_by(BackupRestore.status).all())

    return {
        "stale_days": stale_days,
        "stale_before": stale_before,
        "supported": len(devices),
        "fresh": sum(1 for d in devices if d["state"] == "fresh"),
        "never": sum(1 for d in devices if d["state"] == "never"),
        "stale": sum(1 for d in devices if d["state"] == "stale"),
        "by_family": by_family,
        "attention": attention[:ATTENTION_LIMIT],
        "attention_total": len(attention),
        "backups_30d": {
            "total": sum(sources.values()),
            "manual": sources.get("manual", 0),
            "hardening": sources.get("hardening", 0),
            "pre_restore": sources.get("pre_restore", 0),
        },
        "daily": daily,
        "restores_30d": {
            "total": sum(restores.values()),
            "succeeded": restores.get("succeeded", 0),
            "reverted": restores.get("reverted", 0),
            "failed": restores.get("failed", 0),
            "active": sum(n for s, n in restores.items() if s in RESTORE_ACTIVE_STATUSES),
        },
    }


def restore_history(db: Session, *, group: Optional[str] = None, search: Optional[str] = None,
                    days: Optional[int] = None, offset: int = 0, limit: int = 25):
    """(jobs, total, counts per group) for the Restore History page. The counts
    follow the search and period, not the group, so the filter chips show what
    each one would list."""
    q = db.query(BackupRestore).outerjoin(User, User.id == BackupRestore.requested_by)
    if days:
        q = q.filter(BackupRestore.created_at >= datetime.utcnow() - timedelta(days=days))
    if search and search.strip():
        term = f"%{search.strip()}%"
        q = q.filter(or_(BackupRestore.asset_name.ilike(term), BackupRestore.device_ip.ilike(term),
                         BackupRestore.reason.ilike(term), User.username.ilike(term)))

    by_status = dict(q.with_entities(BackupRestore.status, func.count(BackupRestore.id))
                     .group_by(BackupRestore.status).all())
    counts = {"all": sum(by_status.values())}
    for name, statuses in RESTORE_GROUPS.items():
        counts[name] = sum(by_status.get(s, 0) for s in statuses)

    if group in RESTORE_GROUPS:
        q = q.filter(BackupRestore.status.in_(RESTORE_GROUPS[group]))
    total = q.count()
    jobs = q.order_by(BackupRestore.created_at.desc(), BackupRestore.id.desc()).offset(offset).limit(limit).all()
    return jobs, total, counts
