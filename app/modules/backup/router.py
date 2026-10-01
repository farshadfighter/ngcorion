"""
Backup Router

API endpoints for managing device configuration backups.
"""
import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.core.ssh_exceptions import SSHConnectionError
from app.models import User, Asset, DeviceBackup
from app.models.backup_restore import RESTORE_ACTIVE_STATUSES, BackupRestore
from app.modules.backup.restore import service as restore_service
from app.modules.backup.restore.drivers import SUPPORTED_FAMILIES, Credentials
from app.modules.backup.overview import RESTORE_GROUPS, compute_overview, restore_history

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/backups", tags=["Backups"])


# ============================================
# Pydantic Schemas
# ============================================

class BackupSummary(BaseModel):
    id: int
    asset_id: int
    asset_name: Optional[str]
    device_ip: Optional[str]
    device_type: Optional[str]
    source: str
    hardening_action_id: Optional[int]
    created_by: Optional[int]
    created_by_username: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class BackupDetail(BackupSummary):
    config_content: str


class ManualBackupRequest(BaseModel):
    asset_id: int
    device_type: str  # cisco | fortinet
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

    result = []
    for b in backups:
        username = b.user.username if b.user else None
        result.append(BackupSummary(
            id=b.id,
            asset_id=b.asset_id,
            asset_name=b.asset_name,
            device_ip=b.device_ip,
            device_type=b.device_type,
            source=b.source,
            hardening_action_id=b.hardening_action_id,
            created_by=b.created_by,
            created_by_username=username,
            created_at=b.created_at,
        ))

    return result


class BackupAssetGroup(BaseModel):
    asset_id: int
    asset_name: Optional[str]
    device_ip: Optional[str]
    device_type: Optional[str]
    backup_count: int
    manual_count: int
    hardening_count: int
    pre_restore_count: int = 0
    icon: str = "other"
    last_backup_at: Optional[datetime]


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
        func.max(DeviceBackup.created_at).label("last_backup_at"),
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
            last_backup_at=row.last_backup_at,
        )
        for row in rows
    ]


# ============================================
# Restore
# ============================================
# Declared before "/{backup_id}" so "/restores" is not parsed as a backup id.

class RestoreConnection(BaseModel):
    ssh_username: str = Field(..., min_length=1, max_length=255)
    ssh_password: str = Field(..., min_length=1, max_length=255)
    ssh_secret: Optional[str] = Field(None, max_length=255)
    sudo_password: Optional[str] = Field(None, max_length=255)
    ssh_port: int = Field(22, ge=1, le=65535)


class RestoreRequest(RestoreConnection):
    reason: str = Field(..., min_length=5, max_length=1000)
    confirm_name: str = Field(..., max_length=255)
    revert_minutes: int = Field(10, ge=5, le=15)
    live_fingerprint: str = Field(..., min_length=64, max_length=64)
    acknowledge_lockout: bool = False
    allow_without_auto_revert: bool = False


class RestoreJobResponse(BaseModel):
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
        requested_by=current_user.id, created_at=datetime.utcnow(),
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
    query = db.query(BackupRestore)
    if asset_id:
        query = query.filter(BackupRestore.asset_id == asset_id)
    return [_restore_job_response(j) for j in query.order_by(BackupRestore.created_at.desc()).limit(limit)]


# ============================================
# Overview
# ============================================

class AttentionDevice(BaseModel):
    asset_id: int
    asset_name: Optional[str]
    ip_address: Optional[str]
    icon: str
    family: str
    last_backup_at: Optional[datetime]
    state: str          # never | stale


class FamilyCoverage(BaseModel):
    family: str
    label: str
    total: int
    fresh: int


class BackupOverview(BaseModel):
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
    job = db.get(BackupRestore, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Restore not found")
    return _restore_job_response(job)


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

    username = backup.user.username if backup.user else None
    return BackupDetail(
        id=backup.id,
        asset_id=backup.asset_id,
        asset_name=backup.asset_name,
        device_ip=backup.device_ip,
        device_type=backup.device_type,
        source=backup.source,
        hardening_action_id=backup.hardening_action_id,
        created_by=backup.created_by,
        created_by_username=username,
        created_at=backup.created_at,
        config_content=backup.config_content,
    )


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
    device_type = request.device_type.lower()

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

    return BackupSummary(
        id=backup.id,
        asset_id=backup.asset_id,
        asset_name=backup.asset_name,
        device_ip=backup.device_ip,
        device_type=backup.device_type,
        source=backup.source,
        hardening_action_id=backup.hardening_action_id,
        created_by=backup.created_by,
        created_by_username=current_user.username,
        created_at=backup.created_at,
    )


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

def _take_backup(
    device_type: str,
    ip: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
    port: int = 22,
) -> str:
    """Connect to a device and snapshot its configuration.

    Every family exposes the same ``backup_config()`` the pre-hardening flow uses,
    so a manual backup captures exactly what a hardening run would roll back to.
    The SSH families all take the same credentials this request carries.
    """
    if device_type == "cisco":
        from app.modules.cisco.hardening.ssh_executor import CiscoHardeningExecutor
        with CiscoHardeningExecutor(ip=ip, username=username, password=password, secret=secret) as ex:
            return ex.backup_config()
    elif device_type == "fortinet":
        from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor
        with FortiGateHardeningExecutor(ip=ip, username=username, password=password, port=port) as ex:
            return ex.backup_config()
    elif device_type == "linux":
        from app.modules.linux.hardening.ssh_executor import LinuxSSHExecutor
        with LinuxSSHExecutor(ip=ip, username=username, password=password, port=port) as ex:
            return ex.backup_config()
    elif device_type == "apache":
        from app.modules.apache.hardening.ssh_executor import ApacheSSHExecutor
        with ApacheSSHExecutor(ip=ip, username=username, password=password, port=port) as ex:
            return ex.backup_config()
    elif device_type == "mongodb":
        from app.modules.mongodb.hardening.ssh_executor import MongoDBSSHExecutor
        with MongoDBSSHExecutor(ip=ip, username=username, password=password, ssh_port=port) as ex:
            return ex.backup_config()
    else:
        raise ValueError(f"Unsupported device type for manual backup: {device_type}")
