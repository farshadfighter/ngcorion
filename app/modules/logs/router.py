"""
Logs Router - API های لاگ
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
    دریافت تمام لاگ‌های ورود
    
    - **limit**: تعداد رکورد (پیش‌فرض: 50)
    - **success_only**: true=فقط موفق، false=فقط ناموفق، None=همه
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
    دریافت لاگ‌های یک کاربر خاص
    
    - **username**: نام کاربری
    - **limit**: تعداد رکورد (پیش‌فرض: 20)
    """
    logs = db.query(LoginLog).filter(
        LoginLog.username == username
    ).order_by(LoginLog.timestamp.desc()).limit(limit).all()
    
    return logs


@router.get("/stats")
def get_login_stats(db: Session = Depends(get_db)):
    """
    آمار کلی لاگین‌ها
    
    Returns:
        - total_attempts: کل تلاش‌ها
        - successful_logins: تعداد موفق
        - failed_attempts: تعداد ناموفق
        - success_rate: درصد موفقیت
        - recent_successful_logins: 5 لاگین موفق اخیر
    """
    total_attempts = db.query(LoginLog).count()
    successful = db.query(LoginLog).filter(LoginLog.success == True).count()
    failed = db.query(LoginLog).filter(LoginLog.success == False).count()
    
    # آخرین لاگین‌های موفق
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