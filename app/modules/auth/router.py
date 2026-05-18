"""
Auth Router - Login API with Permissions
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import create_access_token
from app.schemas.auth import UserLogin, Token
from app.models import LoginLog, UserRole
from app.models.security_audit_log import log_action
from app.models.user_permission import UserPermission, get_all_modules
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
    """Log login attempt"""
    log_entry = LoginLog(
        username=username,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        message=message,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(log_entry)
    db.commit()
    
    status_text = "Success!" if success else "FAIL!"
    time_str = log_entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{time_str}] Login {status_text}: User '{username}' With IP {ip_address}")


def get_user_permissions(db: Session, user_id: int, user_role: UserRole) -> dict:
    """
    Get user permissions as dictionary
    
    Admin users get full permissions for all modules.
    Other users get permissions from database.
    
    Returns:
        {
            "dashboard": {"read": True, "write": False, "delete": False},
            "asset_list": {"read": True, "write": True, "delete": False},
            ...
        }
    """
    # Admin has all permissions
    if user_role == UserRole.ADMIN:
        return {
            module: {"read": True, "write": True, "delete": True}
            for module in get_all_modules()
        }
    
    # Get permissions from database
    permissions = db.query(UserPermission).filter(
        UserPermission.user_id == user_id
    ).all()
    
    # Build permission dict
    result = {}
    for perm in permissions:
        result[perm.module.value] = {
            "read": perm.can_read,
            "write": perm.can_write,
            "delete": perm.can_delete
        }
    
    # Add missing modules with no permissions
    for module in get_all_modules():
        if module not in result:
            result[module] = {"read": False, "write": False, "delete": False}
    
    return result


@router.post("/login", response_model=Token)
def login(
    user_credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    User login
    
    Returns:
        - access_token: JWT token
        - token_type: "bearer"
        - username: User's username
        - role: User's role (admin, manager, user, guest)
        - permissions: Dictionary of module permissions
    """
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    auth_service = AuthService(db)
    user = auth_service.authenticate_user(
        user_credentials.username, 
        user_credentials.password
    )
    
    if not user:
        log_login_attempt(
            db=db,
            username=user_credentials.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            message="Incorrect username or password"
        )
        log_action(
            db=db,
            username=user_credentials.username,
            action="auth.login",
            module="auth",
            ip_address=client_ip,
            result="failed",
            detail="Incorrect username or password",
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
        log_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="auth.login",
            module="auth",
            target_id=user.id,
            ip_address=client_ip,
            result="failed",
            detail="Account is inactive",
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
    log_action(
        db=db,
        user_id=user.id,
        username=user.username,
        action="auth.login",
        module="auth",
        target_id=user.id,
        ip_address=client_ip,
        result="success",
        detail=f"Login successful (role={user.role.value})",
    )
    
    # Create JWT token
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value}
    )
    
    # Get user permissions
    permissions = get_user_permissions(db, user.id, user.role)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role.value,
        "permissions": permissions
    }