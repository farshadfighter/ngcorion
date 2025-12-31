"""
Asset Logs Router

API endpoints for querying asset audit logs.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, AssetLog


class AssetLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[dict] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


router = APIRouter(prefix="/api/asset-logs", tags=["Asset Logs"])


@router.get("/", response_model=List[AssetLogResponse])
def get_asset_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    asset_id: Optional[int] = None,
    user_id: Optional[int] = None,
    current_user: User = Depends(require_permission("ASSET_LIST", "read")),
    db: Session = Depends(get_db)
):
    """
    Get asset audit logs with filters.

    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    - **offset**: Number of logs to skip (for pagination)
    - **action**: Filter by action type (create, update, delete, excel_import)
    - **asset_id**: Filter by asset ID
    - **user_id**: Filter by user who performed the action
    """
    query = db.query(AssetLog)

    if action:
        query = query.filter(AssetLog.action == action)
    if asset_id:
        query = query.filter(AssetLog.asset_id == asset_id)
    if user_id:
        query = query.filter(AssetLog.user_id == user_id)

    logs = query.order_by(AssetLog.timestamp.desc()).offset(offset).limit(limit).all()

    result = []
    for log in logs:
        log_dict = AssetLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            ip_address=log.ip_address,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/asset/{asset_id}", response_model=List[AssetLogResponse])
def get_logs_for_asset(
    asset_id: int,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_permission("ASSET_LIST", "read")),
    db: Session = Depends(get_db)
):
    """
    Get all logs for a specific asset.

    - **asset_id**: The asset ID to get logs for
    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    """
    logs = db.query(AssetLog).filter(
        AssetLog.asset_id == asset_id
    ).order_by(AssetLog.timestamp.desc()).limit(limit).all()

    result = []
    for log in logs:
        log_dict = AssetLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            ip_address=log.ip_address,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/stats")
def get_asset_log_stats(
    current_user: User = Depends(require_permission("ASSET_LIST", "read")),
    db: Session = Depends(get_db)
):
    """
    Get statistics for asset logs.

    Returns:
        - total: Total number of logs
        - by_action: Count by action type
    """
    total = db.query(AssetLog).count()

    by_action = {}
    for action in ["create", "update", "delete", "excel_import"]:
        by_action[action] = db.query(AssetLog).filter(
            AssetLog.action == action
        ).count()

    return {
        "total": total,
        "by_action": by_action
    }
