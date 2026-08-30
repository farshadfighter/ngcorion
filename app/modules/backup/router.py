"""
Backup Router

API endpoints for managing device configuration backups.
"""
import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, Asset, DeviceBackup

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

    return [
        BackupAssetGroup(
            asset_id=row.asset_id,
            asset_name=row.asset_name,
            device_ip=row.device_ip,
            device_type=row.device_type,
            backup_count=int(row.backup_count or 0),
            manual_count=int(row.manual_count or 0),
            hardening_count=int(row.hardening_count or 0),
            last_backup_at=row.last_backup_at,
        )
        for row in rows
    ]


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
