"""
Audit Module Logs Router

API endpoints for querying audit module logs.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, AuditModuleLog


class AuditModuleLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    session_id: Optional[int] = None
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    target_ip: Optional[str] = None
    audit_type: Optional[str] = None
    profile: Optional[str] = None
    details: Optional[dict] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True


router = APIRouter(prefix="/api/audit-logs", tags=["Audit Module Logs"])


@router.get("/", response_model=List[AuditModuleLogResponse])
def get_audit_module_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    asset_id: Optional[int] = None,
    user_id: Optional[int] = None,
    audit_type: Optional[str] = None,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get audit module logs with filters.

    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    - **offset**: Number of logs to skip (for pagination)
    - **action**: Filter by action type (execute_audit, delete_session)
    - **asset_id**: Filter by asset ID
    - **user_id**: Filter by user who performed the action
    - **audit_type**: Filter by audit type (cisco_cis, cis_benchmark)
    """
    query = db.query(AuditModuleLog)

    if action:
        query = query.filter(AuditModuleLog.action == action)
    if asset_id:
        query = query.filter(AuditModuleLog.asset_id == asset_id)
    if user_id:
        query = query.filter(AuditModuleLog.user_id == user_id)
    if audit_type:
        query = query.filter(AuditModuleLog.audit_type == audit_type)

    logs = query.order_by(AuditModuleLog.timestamp.desc()).offset(offset).limit(limit).all()

    result = []
    for log in logs:
        log_dict = AuditModuleLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            session_id=log.session_id,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            target_ip=log.target_ip,
            audit_type=log.audit_type,
            profile=log.profile,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/asset/{asset_id}", response_model=List[AuditModuleLogResponse])
def get_logs_for_asset(
    asset_id: int,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get all audit logs for a specific asset.

    - **asset_id**: The asset ID to get logs for
    - **limit**: Maximum number of logs to return (default: 50, max: 500)
    """
    logs = db.query(AuditModuleLog).filter(
        AuditModuleLog.asset_id == asset_id
    ).order_by(AuditModuleLog.timestamp.desc()).limit(limit).all()

    result = []
    for log in logs:
        log_dict = AuditModuleLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username if log.user else None,
            action=log.action,
            session_id=log.session_id,
            asset_id=log.asset_id,
            asset_name=log.asset_name,
            target_ip=log.target_ip,
            audit_type=log.audit_type,
            profile=log.profile,
            details=log.details,
            status=log.status,
            error_message=log.error_message,
            timestamp=log.timestamp
        )
        result.append(log_dict)

    return result


@router.get("/stats")
def get_audit_module_log_stats(
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get statistics for audit module logs.

    Returns:
        - total: Total number of logs
        - by_action: Count by action type
        - success_count: Number of successful actions
        - failed_count: Number of failed actions
        - success_rate: Percentage of successful actions
    """
    total = db.query(AuditModuleLog).count()

    by_action = {}
    for action in ["execute_audit", "delete_session"]:
        by_action[action] = db.query(AuditModuleLog).filter(
            AuditModuleLog.action == action
        ).count()

    success = db.query(AuditModuleLog).filter(AuditModuleLog.status == "success").count()
    failed = db.query(AuditModuleLog).filter(AuditModuleLog.status == "failed").count()

    return {
        "total": total,
        "by_action": by_action,
        "success_count": success,
        "failed_count": failed,
        "success_rate": round((success / total * 100) if total > 0 else 0, 2)
    }
