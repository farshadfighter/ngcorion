"""
Logs Router - API 
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.schemas.log import LoginLogResponse
from app.models import LoginLog

router = APIRouter()


@router.get("/", response_model=List[LoginLogResponse])
def get_all_logs(
    limit: int = 50,
    success_only: Optional[bool] = None,
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
def get_login_stats(db: Session = Depends(get_db)):
    """
    total login log
    
    Returns:
        - total_attempts: 
        - successful_logins: 
        - failed_attempts:
        - success_rate: 
        - recent_successful_logins: 
    """
    total_attempts = db.query(LoginLog).count()
    successful = db.query(LoginLog).filter(LoginLog.success == True).count()
    failed = db.query(LoginLog).filter(LoginLog.success == False).count()
    
# last success login
    recent_logins = db.query(LoginLog).filter(
        LoginLog.success == True
    ).order_by(LoginLog.timestamp.desc()).limit(5).all()
    
    return {
        "total_attempts": total_attempts,
        "successful_logins": successful,
        "failed_attempts": failed,
        "success_rate": round((successful / total_attempts * 100) if total_attempts > 0 else 0, 2),
        "recent_successful_logins": [
            {
                "username": log.username,
                "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "ip_address": log.ip_address
            }
            for log in recent_logins
        ]
    }