"""
Backup Router

API endpoints for managing device configuration backups.
"""
import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.core.singleton import runner_tag
from app.core.dependencies import require_permission
from app.core.ssh_exceptions import SSHConnectionError
from app.models import User, Asset, DeviceBackup
from app.models.backup_restore import RESTORE_ACTIVE_STATUSES, BackupRestore
from app.modules.backup.restore import service as restore_service
from app.modules.backup.restore.drivers import SUPPORTED_FAMILIES, Credentials, RestoreApplyError
from app.modules.backup.overview import (RESTORE_GROUPS, backup_family, compute_overview,
                                         last_backup_types, restore_history)
from app.modules.backup import changes  # noqa: F401 - registers the change summary of every new backup
from app.modules.backup import retention

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/backups", tags=["Backups"])


# ============================================
# Pydantic Schemas
# ============================================

class BackupSummary(BaseModel):
    """A stored backup without its content."""
    id: int
    asset_id: int
    asset_name: Optional[str]
    device_ip: Optional[str]
    device_type: Optional[str]
    source: str
    hardening_action_id: Optional[int]
    created_by: Optional[int]
    created_by_username: Optional[str] = None
    created_at: Optional[datetime]
    # compared with the asset's previous backup when it was saved
    previous_backup_id: Optional[int] = None
    changed: Optional[bool] = None
    added_lines: Optional[int] = None
    removed_lines: Optional[int] = None
    change_origin: Optional[str] = None
    change_ref: Optional[str] = None
    confirmed_at: Optional[datetime] = None
    group_run_id: Optional[int] = None
    # a backup taken because the device reported the change over syslog: who changed it, from where
    reported_by: Optional[str] = None
    reported_from: Optional[str] = None
    reported_at: Optional[datetime] = None

    class Config:
        from_attributes = True


def _summary(b: DeviceBackup, username: Optional[str] = None, report: Optional[dict] = None) -> "BackupSummary":
    out = BackupSummary.model_validate(b)
    out.created_by_username = username if username is not None else (b.user.username if b.user else None)
    for key, value in (report or {}).items():
        setattr(out, key, value)
    return out


def _summaries(db: Session, backups: List[DeviceBackup]) -> List["BackupSummary"]:
    from app.modules.syslog.config_changes import reports_for
    reports = reports_for(db, [b.id for b in backups if b.source == "on_change"])
    return [_summary(b, report=reports.get(b.id)) for b in backups]


class BackupDetail(BackupSummary):
    """A stored backup with its configuration content."""
    config_content: str


class ManualBackupRequest(BaseModel):
    """Body of taking a backup now; the SSH credentials are used once and not stored. Without a
    device type the backup is taken as the family detected for the asset (GET /devices)."""
    asset_id: int
    device_type: Optional[str] = None  # cisco | fortinet | linux | apache | mongodb
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    ssh_port: int = 22


# ============================================
# Endpoints
# ============================================

@router.get("/", response_model=List[BackupSummary])
def list_backups(
    asset_id: Optional[int] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """List all device backups (config content excluded for performance)."""
    query = db.query(DeviceBackup)

    if asset_id:
        query = query.filter(DeviceBackup.asset_id == asset_id)
    if source:
        query = query.filter(DeviceBackup.source == source)

    backups = query.order_by(DeviceBackup.created_at.desc()).offset(offset).limit(limit).all()

    return _summaries(db, backups)


class BackupAssetGroup(BaseModel):
    """Backups of one asset, counted by source, for the grouped list."""
    asset_id: int
    asset_name: Optional[str]
    device_ip: Optional[str]
    device_type: Optional[str]
    backup_count: int
    manual_count: int
    hardening_count: int
    pre_restore_count: int = 0
    scheduled_count: int = 0
    # configuration changes found, and how many of them were made outside NGCorion
    change_count: int = 0
    external_change_count: int = 0
    last_change_at: Optional[datetime] = None
    icon: str = "other"
    last_backup_at: Optional[datetime]
    # last time a scheduled backup found the configuration unchanged
    last_confirmed_at: Optional[datetime] = None


@router.get("/by-asset", response_model=List[BackupAssetGroup])
def list_backups_by_asset(
    search: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """One row per asset that has backups, with its counts and latest date.

    Grouped in SQL rather than by paging through /api/backups and counting
    client-side: that list caps at 500 rows, so on a large estate assets would
    silently drop off the list.
    """
    query = db.query(
        DeviceBackup.asset_id,
        func.max(DeviceBackup.asset_name).label("asset_name"),
        func.max(DeviceBackup.device_ip).label("device_ip"),
        func.max(DeviceBackup.device_type).label("device_type"),
        func.count(DeviceBackup.id).label("backup_count"),
        func.sum(
            case((DeviceBackup.source == "manual", 1), else_=0)
        ).label("manual_count"),
        func.sum(
            case((DeviceBackup.source == "hardening", 1), else_=0)
        ).label("hardening_count"),
        func.sum(
            case((DeviceBackup.source == "pre_restore", 1), else_=0)
        ).label("pre_restore_count"),
        func.sum(case((DeviceBackup.source.in_(("scheduled", "on_change")), 1), else_=0)).label("scheduled_count"),
        func.sum(case((DeviceBackup.changed.is_(True), 1), else_=0)).label("change_count"),
        func.sum(case(((DeviceBackup.changed.is_(True)) & (DeviceBackup.change_origin == "external"), 1),
                      else_=0)).label("external_change_count"),
        func.max(case((DeviceBackup.changed.is_(True), DeviceBackup.created_at))).label("last_change_at"),
        func.max(DeviceBackup.created_at).label("last_backup_at"),
        func.max(DeviceBackup.confirmed_at).label("last_confirmed_at"),
    )

    if device_type:
        query = query.filter(DeviceBackup.device_type == device_type)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            (DeviceBackup.asset_name.ilike(term))
            | (DeviceBackup.device_ip.ilike(term))
        )

    rows = (
        query.group_by(DeviceBackup.asset_id)
        .order_by(func.max(DeviceBackup.created_at).desc())
        .all()
    )

    # The asset's own icon; one extra query for the whole page, not per row.
    assets = {
        a.id: a for a in db.query(Asset).options(joinedload(Asset.asset_type))
        .filter(Asset.id.in_([row.asset_id for row in rows])).all()
    } if rows else {}

    return [
        BackupAssetGroup(
            asset_id=row.asset_id,
            icon=assets[row.asset_id].resolved_icon if row.asset_id in assets else "other",
            asset_name=row.asset_name,
            device_ip=row.device_ip,
            device_type=row.device_type,
            backup_count=int(row.backup_count or 0),
            manual_count=int(row.manual_count or 0),
            hardening_count=int(row.hardening_count or 0),
            pre_restore_count=int(row.pre_restore_count or 0),
            scheduled_count=int(row.scheduled_count or 0),
            change_count=int(row.change_count or 0),
            external_change_count=int(row.external_change_count or 0),
            last_change_at=row.last_change_at,
            last_backup_at=row.last_backup_at,
            last_confirmed_at=row.last_confirmed_at,
        )
        for row in rows
    ]


# ============================================
# Restore
# ============================================
# Declared before "/{backup_id}" so "/restores" is not parsed as a backup id.

class RestoreConnection(BaseModel):
    """SSH credentials for a restore preview or run; used for that request only."""
    ssh_username: str = Field(..., min_length=1, max_length=255)
    ssh_password: str = Field(..., min_length=1, max_length=255)
    ssh_secret: Optional[str] = Field(None, max_length=255)
    sudo_password: Optional[str] = Field(None, max_length=255)
    ssh_port: int = Field(22, ge=1, le=65535)


class RestoreRequest(RestoreConnection):
    """Body of a restore: a reason, the device name typed again as confirmation, the revert window, the
    live-configuration fingerprint from the preview, and explicit consent for lockout risk or a
    restore without auto-revert.
    """
    reason: str = Field(..., min_length=5, max_length=1000)
    confirm_name: str = Field(..., max_length=255)
    revert_minutes: int = Field(10, ge=5, le=15)
    live_fingerprint: str = Field(..., min_length=64, max_length=64)
    acknowledge_lockout: bool = False
    allow_without_auto_revert: bool = False


class RestoreJobResponse(BaseModel):
    """A restore job with its status and step log."""
    id: int
    backup_id: Optional[int]
    asset_id: int
    asset_name: Optional[str]
    device_ip: Optional[str]
    device_type: str
    status: str
    reason: str
    revert_minutes: int
    auto_revert: str
    pre_restore_backup_id: Optional[int]
    diff_summary: Optional[dict]
    events: list
    error: Optional[str]
    requested_by_username: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]


def _restore_job_response(job: BackupRestore) -> RestoreJobResponse:
    return RestoreJobResponse(
        id=job.id, backup_id=job.backup_id, asset_id=job.asset_id, asset_name=job.asset_name,
        device_ip=job.device_ip, device_type=job.device_type, status=job.status, reason=job.reason,
        revert_minutes=job.revert_minutes, auto_revert=job.auto_revert,
        pre_restore_backup_id=job.pre_restore_backup_id, diff_summary=job.diff_summary,
        events=job.events or [], error=job.error,
        requested_by_username=job.user.username if job.user else None,
        created_at=job.created_at, started_at=job.started_at, finished_at=job.finished_at,
    )


def _restorable(backup_id: int, current_user: User, db: Session):
    """Restore rewrites a live device: Admin or Manager (with backup write) only."""
    if current_user.role.value not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Only an Admin or Manager can restore a backup")
    backup = db.query(DeviceBackup).filter(DeviceBackup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    if (backup.device_type or "").lower() not in SUPPORTED_FAMILIES:
        raise HTTPException(status_code=400, detail=f"Restore is not supported for '{backup.device_type}' backups")
    asset = db.query(Asset).filter(Asset.id == backup.asset_id).first()
    if not asset or not asset.ip_address:
        raise HTTPException(status_code=400, detail="The backup's asset no longer exists or has no IP address")
    return backup, asset


def _credentials(body: RestoreConnection, asset: Asset) -> Credentials:
    return Credentials(host=asset.ip_address, username=body.ssh_username, password=body.ssh_password,
                       port=body.ssh_port, secret=body.ssh_secret, sudo_password=body.sudo_password)


@router.post("/{backup_id}/restore/preview")
def preview_restore(
    backup_id: int,
    body: RestoreConnection,
    current_user: User = Depends(require_permission("backup", "write")),
    db: Session = Depends(get_db),
):
    """Connect, read the live configuration and return what a restore would change.
    Read-only: nothing is written to the device."""
    backup, asset = _restorable(backup_id, current_user, db)
    try:
        result = restore_service.preview(backup, _credentials(body, asset))
    except SSHConnectionError as exc:
        raise HTTPException(status_code=exc.http_status, detail=exc.to_dict())
    except RestoreApplyError as exc:
        # The device answered but refused (no sudo, a missing file): say what it said.
        logger.warning("Restore preview of backup %s refused by the device: %s", backup_id, exc)
        raise HTTPException(status_code=502, detail=f"Could not read the device's configuration: {exc}")
    except Exception:
        logger.exception("Restore preview failed for backup %s", backup_id)
        raise HTTPException(status_code=502, detail="Could not read the device's configuration. See the server logs for details.")
    return {**result, "backup_id": backup.id, "asset_id": asset.id, "asset_name": asset.asset_name,
            "device_ip": asset.ip_address, "device_type": backup.device_type}


@router.post("/{backup_id}/restore", response_model=RestoreJobResponse, status_code=202)
def start_restore(
    backup_id: int,
    body: RestoreRequest,
    current_user: User = Depends(require_permission("backup", "write")),
    db: Session = Depends(get_db),
):
    """Start a restore in the background; poll GET /api/backups/restores/{id}."""
    backup, asset = _restorable(backup_id, current_user, db)
    if body.confirm_name.strip() != (asset.asset_name or "").strip():
        raise HTTPException(status_code=400, detail="The typed asset name does not match")
    active = db.query(BackupRestore).filter(
        BackupRestore.asset_id == asset.id, BackupRestore.status.in_(RESTORE_ACTIVE_STATUSES)
    ).first()
    if active:
        raise HTTPException(status_code=409, detail=f"Restore #{active.id} is already running on this asset")

    job = BackupRestore(
        backup_id=backup.id, asset_id=asset.id, asset_name=asset.asset_name, device_ip=asset.ip_address,
        device_type=backup.device_type.lower(), status="queued", reason=body.reason.strip(),
        revert_minutes=body.revert_minutes, auto_revert="unavailable", events=[],
        requested_by=current_user.id, created_at=datetime.utcnow(), runner=runner_tag(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    restore_service.start_restore(job.id, _credentials(body, asset), body.live_fingerprint,
                                  body.acknowledge_lockout, body.allow_without_auto_revert)
    return _restore_job_response(job)


@router.get("/restores", response_model=List[RestoreJobResponse])
def list_restores(
    asset_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """Recent restore jobs, optionally for one asset."""
    query = db.query(BackupRestore)
    if asset_id:
        query = query.filter(BackupRestore.asset_id == asset_id)
    return [_restore_job_response(j) for j in query.order_by(BackupRestore.created_at.desc()).limit(limit)]


# ============================================
# Overview
# ============================================

class AttentionDevice(BaseModel):
    """A device with no backup or only an old one."""
    asset_id: int
    asset_name: Optional[str]
    ip_address: Optional[str]
    icon: str
    family: str
    last_backup_at: Optional[datetime]
    state: str          # never | stale


class FamilyCoverage(BaseModel):
    """Backup coverage of one device family."""
    family: str
    label: str
    total: int
    fresh: int


class BackupOverview(BaseModel):
    """Backup coverage for the backup page header."""
    stale_days: int
    stale_before: datetime
    supported: int
    fresh: int
    never: int
    stale: int
    by_family: List[FamilyCoverage]
    attention: List[AttentionDevice]
    attention_total: int
    backups_30d: dict
    daily: List[dict]
    restores_30d: dict
    recent_restores: List[RestoreJobResponse] = []


@router.get("/overview", response_model=BackupOverview)
def backup_overview(
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """Coverage of the supported devices, what needs a backup, recent activity."""
    data = compute_overview(db)
    recent = db.query(BackupRestore).order_by(BackupRestore.created_at.desc(), BackupRestore.id.desc()).limit(5)
    data["recent_restores"] = [_restore_job_response(j) for j in recent]
    return data


class RestoreHistoryPage(BaseModel):
    """One page of restore history with counts per status."""
    items: List[RestoreJobResponse]
    total: int
    counts: dict


@router.get("/restores/history", response_model=RestoreHistoryPage)
def list_restore_history(
    status: Optional[str] = Query(None, pattern="^(" + "|".join(RESTORE_GROUPS) + ")$"),
    search: Optional[str] = Query(None, max_length=200),
    days: Optional[int] = Query(90, ge=1, le=3650),
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=200),
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """Restore History page: filtered, paged, with a count per result."""
    jobs, total, counts = restore_history(db, group=status, search=search, days=days, offset=offset, limit=limit)
    return RestoreHistoryPage(items=[_restore_job_response(j) for j in jobs], total=total, counts=counts)


@router.get("/restores/{job_id}", response_model=RestoreJobResponse)
def get_restore(
    job_id: int,
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """One restore job, polled by the UI while it runs."""
    job = db.get(BackupRestore, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Restore not found")
    return _restore_job_response(job)


class DiffLineOut(BaseModel):
    op: str
    text: str


class DiffSectionOut(BaseModel):
    title: str
    lines: List[DiffLineOut]


class CompareResponse(BaseModel):
    """What changed from one backup of an asset to another ("+" in the newer only, "-" in the older
    only)."""
    old: BackupSummary
    new: BackupSummary
    added: int
    removed: int
    sections: List[DiffSectionOut]
    truncated: bool = False


class BackupSettings(BaseModel):
    retention_days: int = Field(..., ge=retention.MIN_DAYS, le=retention.MAX_DAYS)


@router.get("/compare", response_model=CompareResponse)
def compare_backups(
    old: int = Query(..., description="the older backup"),
    new: int = Query(..., description="the newer backup"),
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """Compare two backups of the same asset, in configuration order (Cisco IOS and FortiOS as
    configuration trees, file bundles file by file)."""
    a, b = db.get(DeviceBackup, old), db.get(DeviceBackup, new)
    if a is None or b is None:
        raise HTTPException(status_code=404, detail="Backup not found")
    if a.asset_id != b.asset_id:
        raise HTTPException(status_code=400, detail="Compare two backups of the same asset")
    if (a.created_at or datetime.min) > (b.created_at or datetime.min):
        a, b = b, a
    diff = changes.compare(b.device_type or a.device_type, a.config_content, b.config_content)
    sections, shown, truncated = [], 0, False
    for sec in diff.sections:
        lines = [DiffLineOut(op=line.op, text=line.text) for line in sec.lines]
        if shown + len(lines) > changes.MAX_LINES_SHOWN:
            lines, truncated = lines[: max(0, changes.MAX_LINES_SHOWN - shown)], True
        shown += len(lines)
        sections.append(DiffSectionOut(title=sec.title, lines=lines))
        if truncated:
            break
    old_out, new_out = _summaries(db, [a, b])
    return CompareResponse(old=old_out, new=new_out, added=diff.added, removed=diff.removed,
                           sections=sections, truncated=truncated)


@router.get("/settings", response_model=BackupSettings)
def get_backup_settings(current_user: User = Depends(require_permission("backup", "read")),
                        db: Session = Depends(get_db)):
    return retention.get_settings(db)


@router.put("/settings", response_model=BackupSettings)
def save_backup_settings(body: BackupSettings, request: Request,
                         current_user: User = Depends(require_permission("backup", "write")),
                         db: Session = Depends(get_db)):
    """How long backups identical to the previous one are kept."""
    from app.models.security_audit_log import log_action
    saved = retention.save_settings(db, body.retention_days, current_user.id)
    log_action(db, user_id=current_user.id, username=current_user.username, action="backup.settings",
               module="backup", ip_address=request.client.host if request.client else None,
               detail=f"Device backups identical to the previous one are kept {saved['retention_days']} days")
    return saved


class BackupDevice(BaseModel):
    """An asset a backup may be taken from, and the device family detected for it (None: unknown)."""
    asset_id: int
    asset_name: str
    ip_address: Optional[str] = None
    family: Optional[str] = None


@router.get("/devices", response_model=List[BackupDevice])
def list_backup_devices(
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """Every asset, by name, with the device family a backup of it is taken as (the New Backup
    dialog's list; the asset list API pages by at most 100)."""
    last = last_backup_types(db)
    return [BackupDevice(asset_id=a.id, asset_name=a.asset_name, ip_address=a.ip_address,
                         family=backup_family(a, last.get(a.id)))
            for a in db.query(Asset).options(joinedload(Asset.asset_type)).order_by(Asset.asset_name)]


@router.get("/{backup_id}", response_model=BackupDetail)
def get_backup(
    backup_id: int,
    current_user: User = Depends(require_permission("backup", "read")),
    db: Session = Depends(get_db),
):
    """Get a single backup including full config content."""
    backup = db.query(DeviceBackup).filter(DeviceBackup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    return BackupDetail(**_summaries(db, [backup])[0].model_dump(), config_content=backup.config_content)


@router.post("/", response_model=BackupSummary, status_code=201)
def create_manual_backup(
    request: ManualBackupRequest,
    current_user: User = Depends(require_permission("backup", "write")),
    db: Session = Depends(get_db),
):
    """Trigger a manual backup for a device by connecting via SSH."""
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if not asset.ip_address:
        raise HTTPException(status_code=400, detail=f"Asset '{asset.asset_name}' has no IP address configured")

    device_ip = asset.ip_address
    device_type = (request.device_type or "").strip().lower() or backup_family(asset, last_backup_types(db).get(asset.id))
    if device_type is None:
        raise HTTPException(status_code=400, detail="Choose the device type; it could not be told from the asset")
    if device_type not in SUPPORTED_FAMILIES:
        raise HTTPException(status_code=400, detail="A backup can be taken from Cisco, Fortinet, Linux, Apache and MongoDB devices")

    try:
        config_content = _take_backup(
            device_type=device_type,
            ip=device_ip,
            username=request.ssh_username,
            password=request.ssh_password,
            secret=request.ssh_secret,
            port=request.ssh_port,
        )
    except Exception as exc:
        logger.error(f"Manual backup failed for asset {request.asset_id}: {exc}")
        raise HTTPException(status_code=502, detail=f"Backup failed: {str(exc)}")

    backup = DeviceBackup(
        asset_id=asset.id,
        asset_name=asset.asset_name,
        device_ip=device_ip,
        device_type=device_type,
        config_content=config_content,
        source="manual",
        hardening_action_id=None,
        created_by=current_user.id,
        created_at=datetime.utcnow(),
    )
    db.add(backup)
    db.commit()
    db.refresh(backup)

    return _summary(backup, current_user.username)


@router.delete("/{backup_id}", status_code=204)
def delete_backup(
    backup_id: int,
    current_user: User = Depends(require_permission("backup", "delete")),
    db: Session = Depends(get_db),
):
    """Delete a backup record."""
    backup = db.query(DeviceBackup).filter(DeviceBackup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    db.delete(backup)
    db.commit()


# ============================================
# Internal Helpers
# ============================================

def _take_backup(device_type: str, ip: str, username: str, password: str,
                 secret: Optional[str] = None, port: int = 22) -> str:
    """Connect to a device and snapshot its configuration (app/modules/backup/collect.py)."""
    from app.modules.backup.collect import take_backup
    return take_backup(device_type, ip, username, password, secret, port)
