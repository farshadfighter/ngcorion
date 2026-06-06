"""
Discovery Logs Router

API endpoints for querying discovery audit logs.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, DiscoveryAuditLog


class DiscoveryLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    scan_id: Optional[str] = None
    asset_id: Optional[int] = None
    ip_address: Optional[str] = None
    target: Optional[str] = None
    details: Optional[dict] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


router = APIRouter(prefix="/api/discovery-logs", tags=["Discovery Logs"])


@router.get("/", response_model=List[DiscoveryLogResponse])
def get_discovery_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    scan_id: Optional[str] = None,
    asset_id: Optional[int] = None,
    user_id: Optional[int] = None,
    status: Optional[str] = None,
    current_user: User = Depends(require_permission("ASSET_AUTO_DISCOVERY", "read")),
    db: Session = Depends(get_db)
):
    """
    Get discovery audit logs with filters.

    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    - **offset**: Number of logs to skip (for pagination)
    - **action**: Filter by action type
    - **scan_id**: Filter by scan ID
    - **asset_id**: Filter by asset ID
    - **user_id**: Filter by user who performed the action
    - **status**: Filter by status (success, failed, partial)
    """
    query = db.query(DiscoveryAuditLog)

    if action:
        query = query.filter(DiscoveryAuditLog.action == action)
    if scan_id:
        query = query.filter(DiscoveryAuditLog.scan_id == scan_id)
    if asset_id:
        query = query.filter(DiscoveryAuditLog.asset_id == asset_id)
    if user_id:
        query = query.filter(DiscoveryAuditLog.user_id == user_id)
    if status:
        query = query.filter(DiscoveryAuditLog.status == status)

    logs = query.order_by(DiscoveryAuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    result = []
    for log in logs:
        log_dict = DiscoveryLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            scan_id=log.scan_id,
            asset_id=log.asset_id,
            ip_address=log.ip_address,
            target=log.target,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/scan/{scan_id}", response_model=List[DiscoveryLogResponse])
def get_logs_for_scan(
    scan_id: str,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_permission("ASSET_AUTO_DISCOVERY", "read")),
    db: Session = Depends(get_db)
):
    """
    Get all logs for a specific scan.

    - **scan_id**: The scan ID to get logs for
    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    """
    logs = db.query(DiscoveryAuditLog).filter(
        DiscoveryAuditLog.scan_id == scan_id
    ).order_by(DiscoveryAuditLog.timestamp.desc()).limit(limit).all()

    result = []
    for log in logs:
        log_dict = DiscoveryLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            scan_id=log.scan_id,
            asset_id=log.asset_id,
            ip_address=log.ip_address,
            target=log.target,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/stats")
def get_discovery_log_stats(
    current_user: User = Depends(require_permission("ASSET_AUTO_DISCOVERY", "read")),
    db: Session = Depends(get_db)
):
    """
    Get statistics for discovery logs.

    Returns:
        - total: Total number of logs
        - by_action: Count by action type
        - by_status: Count by status
    """
    total = db.query(DiscoveryAuditLog).count()

    # Get unique actions
    actions = db.query(DiscoveryAuditLog.action).distinct().all()
    by_action = {}
    for (action,) in actions:
        by_action[action] = db.query(DiscoveryAuditLog).filter(
            DiscoveryAuditLog.action == action
        ).count()

    by_status = {}
    for status in ["success", "failed", "partial", "warning"]:
        count = db.query(DiscoveryAuditLog).filter(
            DiscoveryAuditLog.status == status
        ).count()
        if count > 0:
            by_status[status] = count

    return {
        "total": total,
        "by_action": by_action,
        "by_status": by_status
    }
