"""
Auth Router - API لاگین
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.database import get_db
from app.core.security import create_access_token
from app.schemas.auth import UserLogin, Token
from app.models import LoginLog
from .service import AuthService

router = APIRouter()

def log_login_attempt(
    db: Session,
    username: str,
    success: bool,
    ip_address: str,
    user_agent: str,
    message: str = None
):
    """ثبت لاگ تلاش ورود"""
    log_entry = LoginLog(
        username=username,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        message=message,
        timestamp=datetime.utcnow()
    )
    db.add(log_entry)
    db.commit()
    
    status_text = "Success!" if success else "FAIL!"
    time_str = log_entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{time_str}] Login {status_text}: User '{username}' With IP {ip_address}")

@router.post("/login", response_model=Token)
def login(
    user_credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    auth_service = AuthService(db)
    user = auth_service.authenticate_user(user_credentials.username, user_credentials.password)
    
    if not user:
        log_login_attempt(
            db=db,
            username=user_credentials.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            message="Incorrect username or password"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        log_login_attempt(
            db=db,
            username=user_credentials.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            message="Account is inactive"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )
    
    log_login_attempt(
        db=db,
        username=user.username,
        success=True,
        ip_address=client_ip,
        user_agent=user_agent,
        message=f"Login successfully with {user.role.value} Role."
    )
    
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role.value,
        "username": user.username
    }