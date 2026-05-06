"""
Audit Module Logs Router

API endpoints for querying audit module logs.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Any
from datetime import datetime
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, AuditLog


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
    details: Optional[Any] = None
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
    """
    query = db.query(AuditLog)

    # Filtering based on the new AuditLog columns
    if action:
        query = query.filter(AuditLog.action == action)
    if asset_id:
        query = query.filter(AuditLog.target_id == asset_id)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if audit_type:
        query = query.filter(AuditLog.module == audit_type)

    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    result = []
    for log in logs:
        # Extracting username if relation exists
        username = None
        if hasattr(log, "user") and log.user:
             username = log.user.username

        log_dict = AuditModuleLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=username,
            action=log.action,
            session_id=None, # session details are now stored in `detail` string
            asset_id=log.target_id, # target_id represents asset_id here
            asset_name=None, 
            target_ip=log.ip_address,
            audit_type=log.module,
            profile=None,
            details={"info": log.detail} if hasattr(log, "detail") else None,
            status=log.result, # status is now 'result' (success/failed)
            error_message=log.detail if log.result == "failed" else None,
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
    """
    logs = db.query(AuditLog).filter(
        AuditLog.target_id == asset_id,
        AuditLog.module.in_(["cisco_cis", "cisco_audit"]) # Restrict to audit modules
    ).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    result = []
    for log in logs:
        username = None
        if hasattr(log, "user") and log.user:
             username = log.user.username

        log_dict = AuditModuleLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=username,
            action=log.action,
            session_id=None,
            asset_id=log.target_id,
            asset_name=None,
            target_ip=log.ip_address,
            audit_type=log.module,
            profile=None,
            details={"info": log.detail} if hasattr(log, "detail") else None,
            status=log.result,
            error_message=log.detail if log.result == "failed" else None,
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
    """
    # Only count logs related to cisco audit
    base_query = db.query(AuditLog).filter(AuditLog.module.in_(["cisco_cis", "cisco_audit"]))
    
    total = base_query.count()

    by_action = {}
    # Use the new action names you configured earlier
    for action in ["audit_executed", "audit_session_deleted"]:
        by_action[action] = base_query.filter(AuditLog.action == action).count()

    # Use the new 'result' column for success/failed status
    success = base_query.filter(AuditLog.result == "success").count()
    failed = base_query.filter(AuditLog.result == "failed").count()

    return {
        "total": total,
        "by_action": by_action,
        "success_count": success,
        "failed_count": failed,
        "success_rate": round((success / total * 100) if total > 0 else 0, 2)
    }
