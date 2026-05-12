"""
Hardening Logs Router

API endpoints for querying hardening audit logs.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, HardeningLog


class HardeningLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    audit_session_id: Optional[int] = None
    device_type: Optional[str] = None
    check_ids: Optional[list] = None
    check_count: Optional[int] = None
    details: Optional[dict] = None
    status: Optional[str] = None
    success_count: Optional[int] = None
    failed_count: Optional[int] = None
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


router = APIRouter(prefix="/api/hardening-logs", tags=["Hardening Logs"])


@router.get("/", response_model=List[HardeningLogResponse])
def get_hardening_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    device_type: Optional[str] = None,
    asset_id: Optional[int] = None,
    user_id: Optional[int] = None,
    status: Optional[str] = None,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get hardening audit logs with filters.

    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    - **offset**: Number of logs to skip (for pagination)
    - **action**: Filter by action type (preview, execute, batch_execute, auto_harden)
    - **device_type**: Filter by device type (cisco, fortinet, linux, etc.)
    - **asset_id**: Filter by asset ID
    - **user_id**: Filter by user who performed the action
    - **status**: Filter by status (success, failed, partial)
    """
    query = db.query(HardeningLog)

    if action:
        query = query.filter(HardeningLog.action == action)
    if device_type:
        query = query.filter(HardeningLog.device_type == device_type)
    if asset_id:
        query = query.filter(HardeningLog.asset_id == asset_id)
    if user_id:
        query = query.filter(HardeningLog.user_id == user_id)
    if status:
        query = query.filter(HardeningLog.status == status)

    logs = query.order_by(HardeningLog.timestamp.desc()).offset(offset).limit(limit).all()

    result = []
    for log in logs:
        log_dict = HardeningLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            audit_session_id=log.audit_session_id,
            device_type=log.device_type,
            check_ids=log.check_ids,
            check_count=log.check_count,
            details=log.details,
            status=log.status,
            success_count=log.success_count,
            failed_count=log.failed_count,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/asset/{asset_id}", response_model=List[HardeningLogResponse])
def get_logs_for_asset(
    asset_id: int,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get all hardening logs for a specific asset.

    - **asset_id**: The asset ID to get logs for
    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    """
    logs = db.query(HardeningLog).filter(
        HardeningLog.asset_id == asset_id
    ).order_by(HardeningLog.timestamp.desc()).limit(limit).all()

    result = []
    for log in logs:
        log_dict = HardeningLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            audit_session_id=log.audit_session_id,
            device_type=log.device_type,
            check_ids=log.check_ids,
            check_count=log.check_count,
            details=log.details,
            status=log.status,
            success_count=log.success_count,
            failed_count=log.failed_count,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/session/{session_id}", response_model=List[HardeningLogResponse])
def get_logs_for_session(
    session_id: int,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get all hardening logs for a specific audit session.

    - **session_id**: The audit session ID to get logs for
    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    """
    logs = db.query(HardeningLog).filter(
        HardeningLog.audit_session_id == session_id
    ).order_by(HardeningLog.timestamp.desc()).limit(limit).all()

    result = []
    for log in logs:
        log_dict = HardeningLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            audit_session_id=log.audit_session_id,
            device_type=log.device_type,
            check_ids=log.check_ids,
            check_count=log.check_count,
            details=log.details,
            status=log.status,
            success_count=log.success_count,
            failed_count=log.failed_count,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/stats")
def get_hardening_log_stats(
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get statistics for hardening logs.

    Returns:
        - total: Total number of logs
        - by_action: Count by action type
        - by_device_type: Count by device type
        - by_status: Count by status
    """
    total = db.query(HardeningLog).count()

    by_action = {}
    for action in ["preview", "execute", "batch_execute", "auto_harden"]:
        by_action[action] = db.query(HardeningLog).filter(
            HardeningLog.action == action
        ).count()

    by_device_type = {}
    for device_type in ["cisco", "fortinet", "linux", "apache", "windows", "mssql", "mongodb"]:
        count = db.query(HardeningLog).filter(
            HardeningLog.device_type == device_type
        ).count()
        if count > 0:
            by_device_type[device_type] = count

    by_status = {}
    for status in ["success", "failed", "partial"]:
        by_status[status] = db.query(HardeningLog).filter(
            HardeningLog.status == status
        ).count()

    return {
        "total": total,
        "by_action": by_action,
        "by_device_type": by_device_type,
        "by_status": by_status
    }
