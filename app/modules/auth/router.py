"""
Auth Router - Login API with Permissions
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import create_access_token
from app.core.auth_rate_limiter import (
    check_login_rate_limit,
    check_password_reset_rate_limit,
)
from app.core.config import settings
from app.core.email import send_password_reset_email
from app.schemas.auth import (
    UserLogin,
    Token,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MessageResponse,
)
from app.models import LoginLog, UserRole
from app.models.security_audit_log import log_action
from app.models.user_permission import UserPermission, get_all_modules
from .service import AuthService

# Identical response for any forgot-password request, so callers cannot tell
# whether an account with the given email exists (prevents enumeration).
GENERIC_FORGOT_PASSWORD_MESSAGE = (
    "If an account with that email exists, a password reset link has been sent."
)

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

    try:
        check_login_rate_limit(db, client_ip, user_credentials.username)
    except HTTPException as exc:
        log_login_attempt(
            db=db,
            username=user_credentials.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            message="Rate limited",
        )
        log_action(
            db=db,
            username=user_credentials.username,
            action="auth.login",
            module="auth",
            ip_address=client_ip,
            result="failed",
            detail="Rate limited",
        )
        raise exc

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


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Request a password reset link.

    Always returns the same generic message regardless of whether the email
    matches an account, to avoid leaking which emails are registered.
    """
    client_ip = request.client.host
    email = payload.email

    # Rate limit before creating any token (also caps probing of unknown emails).
    check_password_reset_rate_limit(db, client_ip, email)

    auth_service = AuthService(db)
    result = auth_service.create_password_reset_token(email, ip_address=client_ip)

    if result is not None:
        raw_token, user = result
        reset_link = f"{settings.FRONTEND_BASE_URL}/reset-password?token={raw_token}"
        background_tasks.add_task(send_password_reset_email, user.email, reset_link)
        log_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="auth.forgot_password",
            module="auth",
            target_id=user.id,
            ip_address=client_ip,
            result="success",
            detail="Password reset link generated",
        )
    else:
        # No active account — record the attempt but reveal nothing to the caller.
        log_action(
            db=db,
            username=email,
            action="auth.forgot_password",
            module="auth",
            ip_address=client_ip,
            result="failed",
            detail="No active account for email",
        )

    return {"message": GENERIC_FORGOT_PASSWORD_MESSAGE}


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Set a new password using a token from the reset email.

    The token must be unused and unexpired; it is consumed on success.
    """
    client_ip = request.client.host

    auth_service = AuthService(db)
    user = auth_service.reset_password_with_token(payload.token, payload.new_password)

    if user is None:
        log_action(
            db=db,
            action="auth.reset_password",
            module="auth",
            ip_address=client_ip,
            result="failed",
            detail="Invalid or expired reset token",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset link. Please request a new one.",
        )

    log_action(
        db=db,
        user_id=user.id,
        username=user.username,
        action="auth.reset_password",
        module="auth",
        target_id=user.id,
        ip_address=client_ip,
        result="success",
        detail="Password reset via email link",
    )

    return {"message": "Your password has been reset. You can now log in."}