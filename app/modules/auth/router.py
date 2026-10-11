"""
Auth Router - Login API with Permissions
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.database import get_db
from fastapi.security import HTTPAuthorizationCredentials
import jwt

from app.core.config import settings
from app.core.dependencies import get_current_user, security
from app.models.revoked_token import RevokedToken
from app.core.sessions import open_session
from app.core.security import create_access_token, get_password_hash, password_fingerprint, verify_password
from app.core.auth_rate_limiter import (
    check_login_rate_limit,
    check_password_reset_rate_limit,
)
from app.core.email import send_password_reset_otp
from app.schemas.auth import (
    UserLogin,
    Token,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MessageResponse,
)
from app.models import LoginLog, UserRole, User
from app.models.security_audit_log import log_action
from app.core.locale import user_language
from pydantic import BaseModel, Field, field_validator
from app.schemas.user import validate_password_strength
from typing import Literal
from app.models.user_permission import UserPermission, get_all_modules
from .service import AuthService

router = APIRouter()


def _open_session(db: Session, token: str, user_id: int, ip: str) -> None:
    """Start the idle-timeout record of a token this router just issued."""
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    open_session(db, payload, user_id, ip)


@router.get("/login-banner")
def login_banner():
    """What the login page shows before anyone signs in: the notice (LOGIN_BANNER; null means
    the built-in bilingual one) and the idle timeout the UI signs out after. Public."""
    return {"banner": settings.LOGIN_BANNER or None,
            "idle_timeout_minutes": settings.SESSION_IDLE_TIMEOUT_MINUTES}


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
        data={
            "sub": user.username,
            "role": user.role.value,
            "pwv": password_fingerprint(user.hashed_password),
        }
    )
    _open_session(db, access_token, user.id, client_ip)
    
    # Get user permissions
    permissions = get_user_permissions(db, user.id, user.role)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role.value,
        "permissions": permissions,
        "language": user_language(db, user),
        "language_chosen": bool(user.language),
        "must_change_password": bool(user.must_change_password),
    }


@router.get("/me")
def read_current_user(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Validate the caller's JWT and return the current user's identity/permissions.

    Used by the frontend on app load to confirm the stored token is still valid
    BEFORE rendering any protected route. Returns 401 (via get_current_user) if
    the token is missing, malformed, or expired, and 403 if the account is
    disabled — so an expired session can never slip past the client-side guard.

    Permissions are re-read from the DB so they reflect any changes made since
    the token was issued, rather than trusting the stale copy in localStorage.
    """
    return {
        "username": current_user.username,
        "role": current_user.role.value,
        "permissions": get_user_permissions(db, current_user.id, current_user.role),
        "language": user_language(db, current_user),
        "language_chosen": bool(current_user.language),
        "must_change_password": bool(current_user.must_change_password),
    }


class OwnPasswordChange(BaseModel):
    """Body of PUT /auth/me/password: the current password and a new one that meets the password
    policy.
    """
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., max_length=256)

    @field_validator("new_password")
    @classmethod
    def _strong(cls, v: str) -> str:
        return validate_password_strength(v)


@router.put("/me/password", response_model=Token)
def change_own_password(
    data: OwnPasswordChange,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    The signed-in user changes their own password; no user-management
    permission is needed. The current password must be given (a stolen
    session alone cannot take the account over). Every token issued before
    the change stops working (their password fingerprint no longer matches),
    so the response carries a fresh token for this session.
    """
    client_ip = request.client.host if request.client else None
    if not verify_password(data.current_password, current_user.hashed_password):
        log_action(db, user_id=current_user.id, username=current_user.username, action="auth.password_change",
                   module="auth", target_id=current_user.id, ip_address=client_ip, result="failed",
                   detail="Current password was wrong")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The current password is incorrect.")
    if verify_password(data.new_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="The new password must be different from the current one.")
    current_user.hashed_password = get_password_hash(data.new_password)
    current_user.must_change_password = False
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="auth.password_change",
               module="auth", target_id=current_user.id, ip_address=client_ip, result="success",
               detail="Password changed by the user")
    token = create_access_token(data={"sub": current_user.username, "role": current_user.role.value,
                                      "pwv": password_fingerprint(current_user.hashed_password)})
    _open_session(db, token, current_user.id, client_ip)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": current_user.username,
        "role": current_user.role.value,
        "permissions": get_user_permissions(db, current_user.id, current_user.role),
        "language": user_language(db, current_user),
        "language_chosen": bool(current_user.language),
        "must_change_password": False,
    }


class LanguageUpdate(BaseModel):
    """Body of PUT /auth/me/language."""
    language: Literal["en", "fa"]


@router.put("/me/language")
def set_my_language(
    data: LanguageUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The signed-in user's interface language; remembered on their account."""
    current_user.language = data.language
    db.commit()
    return {"language": data.language}


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    End this session on the server: the presented token is revoked and
    refused from now on, even if a copy of it is still around. Other
    sessions of the same user are not affected. Expired revocations are
    pruned here, since a token past its expiry is refused anyway.
    """
    current_user = get_current_user(credentials, db)
    payload = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    now = datetime.now(timezone.utc)
    db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete(synchronize_session=False)
    jti = payload.get("jti")
    if jti:  # tokens issued before revocation existed have none; they simply expire
        db.add(RevokedToken(jti=str(jti), user_id=current_user.id,
                            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc)))
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="logout", module="auth",
               ip_address=request.client.host if request.client else None)
    return {"message": "Logged out"}


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Request a password reset OTP code.

    Always answers with the same message whether or not the email belongs to an
    active account, so the endpoint cannot be used to enumerate accounts.
    """
    generic = {"message": "If an account exists for this email, a password reset code has been sent."}
    client_ip = request.client.host
    email = payload.email

    # Rate limit before creating any code (also caps probing of unknown emails).
    check_password_reset_rate_limit(db, client_ip, email)

    auth_service = AuthService(db)
    result = auth_service.create_password_reset_otp(email, ip_address=client_ip)

    if result is None:
        log_action(
            db=db,
            username=email,
            action="auth.forgot_password",
            module="auth",
            ip_address=client_ip,
            result="failed",
            detail="No active account for email",
        )
        return generic

    otp, user = result
    background_tasks.add_task(send_password_reset_otp, user.email, otp)
    log_action(
        db=db,
        user_id=user.id,
        username=user.username,
        action="auth.forgot_password",
        module="auth",
        target_id=user.id,
        ip_address=client_ip,
        result="success",
        detail="Password reset code generated",
    )

    return generic


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Set a new password using the OTP code emailed to the account.

    The code must match, be unused and unexpired, and be within the attempt
    limit; it is consumed on success.
    """
    client_ip = request.client.host

    auth_service = AuthService(db)
    user = auth_service.reset_password_with_otp(
        payload.email, payload.otp, payload.new_password
    )

    if user is None:
        log_action(
            db=db,
            username=payload.email,
            action="auth.reset_password",
            module="auth",
            ip_address=client_ip,
            result="failed",
            detail="Invalid or expired reset code",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code. Please request a new one.",
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
        detail="Password reset via emailed OTP",
    )

    return {"message": "Your password has been reset. You can now log in."}