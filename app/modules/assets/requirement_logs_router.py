"""
Asset Requirement Logs Router

API endpoints for querying asset requirement audit logs.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, AssetRequirementLog


class AssetRequirementLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    entity_type: str
    entity_id: Optional[int] = None
    entity_name: Optional[str] = None
    details: Optional[dict] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


router = APIRouter(prefix="/api/asset-requirement-logs", tags=["Asset Requirement Logs"])


@router.get("/", response_model=List[AssetRequirementLogResponse])
def get_requirement_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    user_id: Optional[int] = None,
    current_user: User = Depends(require_permission("ASSET_REQUIREMENT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get asset requirement audit logs with filters.

    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    - **offset**: Number of logs to skip (for pagination)
    - **action**: Filter by action type (create, update, delete, excel_import)
    - **entity_type**: Filter by entity type (asset_type, owner, location, zone, os_catalog, vendor)
    - **user_id**: Filter by user who performed the action
    """
    query = db.query(AssetRequirementLog)

    if action:
        query = query.filter(AssetRequirementLog.action == action)
    if entity_type:
        query = query.filter(AssetRequirementLog.entity_type == entity_type)
    if user_id:
        query = query.filter(AssetRequirementLog.user_id == user_id)

    logs = query.order_by(AssetRequirementLog.timestamp.desc()).offset(offset).limit(limit).all()

    # Enhance with username
    result = []
    for log in logs:
        log_dict = AssetRequirementLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            entity_name=log.entity_name,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/stats")
def get_requirement_log_stats(
    current_user: User = Depends(require_permission("ASSET_REQUIREMENT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get statistics for asset requirement logs.

    Returns:
        - total: Total number of logs
        - by_action: Count by action type
        - by_entity_type: Count by entity type
    """
    total = db.query(AssetRequirementLog).count()

    by_action = {}
    for action in ["create", "update", "delete", "excel_import"]:
        by_action[action] = db.query(AssetRequirementLog).filter(
            AssetRequirementLog.action == action
        ).count()

    by_entity_type = {}
    for entity in ["asset_type", "owner", "location", "zone", "os_catalog", "vendor", "multiple"]:
        by_entity_type[entity] = db.query(AssetRequirementLog).filter(
            AssetRequirementLog.entity_type == entity
        ).count()

    return {
        "total": total,
        "by_action": by_action,
        "by_entity_type": by_entity_type
    }
