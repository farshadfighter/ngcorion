"""
Logs Router - API

Every route is gated on the LOGS module permission, matching the
require_permission(module, type) pattern used across the codebase and the
DELETE /api/logs/clear route in clear_router.py. Login history names accounts
and source IPs, so it is not readable by any authenticated user: it needs LOGS
read, which an admin grants from User Management -> System Log.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.schemas.log import LoginLogResponse
from app.models import LoginLog, User

router = APIRouter()


@router.get("/", response_model=List[LoginLogResponse])
def get_all_logs(
    limit: int = 50,
    success_only: Optional[bool] = None,
    _current_user: User = Depends(require_permission("LOGS", "read")),
    db: Session = Depends(get_db)
):
    """
  Get all input logs
    
    - **limit**:(Default: 50)
    - **success_only**: true=only success, false=Only failed ,None= All
    """
    query = db.query(LoginLog)
    
    if success_only is not None:
        query = query.filter(LoginLog.success == success_only)
    
    logs = query.order_by(LoginLog.timestamp.desc()).limit(limit).all()
    return logs


@router.get("/user/{username}", response_model=List[LoginLogResponse])
def get_user_logs(
    username: str,
    limit: int = 20,
    _current_user: User = Depends(require_permission("LOGS", "read")),
    db: Session = Depends(get_db)
):
    """
    Get special user log
    
    - **username**: username
    - **limit**: (Default: 20)
    """
    logs = db.query(LoginLog).filter(
        LoginLog.username == username
    ).order_by(LoginLog.timestamp.desc()).limit(limit).all()
    
    return logs


@router.get("/stats")
def get_login_stats(
    _current_user: User = Depends(require_permission("LOGS", "read")),
    db: Session = Depends(get_db),
):
    """
    Login attempt statistics.

    Returns:
        - total_attempts
        - successful_logins
        - failed_attempts
        - success_rate (percentage)
        - recent_successful_logins (last 5)
        - recent_failed_logins (last 5)
    """
    total_attempts = db.query(LoginLog).count()
    successful = db.query(LoginLog).filter(LoginLog.success == True).count()
    failed = db.query(LoginLog).filter(LoginLog.success == False).count()

    recent_successes = db.query(LoginLog).filter(
        LoginLog.success == True
    ).order_by(LoginLog.timestamp.desc()).limit(5).all()

    recent_failures = db.query(LoginLog).filter(
        LoginLog.success == False
    ).order_by(LoginLog.timestamp.desc()).limit(5).all()

    def _serialize(log: LoginLog) -> dict:
        return {
            "username": log.username,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "ip_address": log.ip_address,
            "message": log.message,
        }

    return {
        "total_attempts": total_attempts,
        "successful_logins": successful,
        "failed_attempts": failed,
        "success_rate": round((successful / total_attempts * 100) if total_attempts > 0 else 0, 2),
        "recent_successful_logins": [_serialize(log) for log in recent_successes],
        "recent_failed_logins": [_serialize(log) for log in recent_failures],
    }