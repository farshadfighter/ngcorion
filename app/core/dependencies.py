"""
Dependencies for authentication and authorization.

Provides FastAPI dependency functions for:
- JWT token validation
- User authentication
- Role-based access control
- (The license's asset limit is enforced in app/core/asset_entitlement.py)
"""
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.orm import Session
from app.core import api_keys, mfa
from app.core.config import settings
from app.core.sessions import touch as touch_session
from app.core.database import get_db
from app.core.security import password_fingerprint
from app.core.storage_guard import check_request as check_storage
from app.models import User
from app.models.revoked_token import RevokedToken

import logging
import requests

logger = logging.getLogger(__name__)

security = HTTPBearer()


def license_error_detail(exc: requests.HTTPError, fallback: str) -> str:
    """
    Pull the license server's own error message out of an HTTPError.

    The body is not guaranteed to be JSON (a proxy or a crashed worker can send
    HTML), and calling .json() on it raised a JSONDecodeError *inside* the
    exception handler — turning an actionable refusal into an opaque
    500. Falls back to the raw body, then to `fallback`.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return str(exc) or fallback
    try:
        payload = response.json()
        if isinstance(payload, dict) and payload.get("detail"):
            return str(payload["detail"])
    except ValueError:
        pass
    body = (response.text or "").strip()
    if body:
        return f"{fallback} (license server said: {body[:200]})"
    return fallback


# What an account whose password was chosen by someone else may still reach
# (User.must_change_password): set its own password, see who it is, sign out.
PASSWORD_CHANGE_ALLOWED = frozenset({"/auth/me", "/auth/me/password", "/auth/me/language", "/auth/logout"})


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
    request: Request = None,
) -> User:
    """
    Validate JWT token and return the authenticated user.

    Args:
        credentials: Bearer token from Authorization header
        db: Database session

    Returns:
        User: Authenticated user object

    Raises:
        HTTPException: 401 if token is invalid, expired, or user not found
        HTTPException: 403 if user account is disabled
    """
    token = credentials.credentials

    # An API key of another system (app/core/api_keys.py): its service account, with the key's scopes as
    # its permissions. Two-step sign-in, password and session rules are for people, not for a key.
    if api_keys.is_api_key(token):
        user = api_keys.authenticate(db, token, request)
        check_storage(request, user)
        return user

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
                headers={"WWW-Authenticate": "Bearer"}
            )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please login again.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    # A token made for one step of something (the two-step sign-in's mfa token) is not a session.
    if payload.get("purpose"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Logged out: the token's id was revoked (server-side logout).
    if payload.get("jti") and db.get(RevokedToken, str(payload["jti"])) is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has ended. Please login again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(User).filter(User.username == username).first()
    # pwv: the password changed since; mfv: two-step sign-in was turned on/off or reset since
    # (a token from before two-step sign-in existed has no mfv, which matches version 0).
    mfa_row = mfa.get_row(db, user.id) if user is not None else None
    if (user is None or payload.get("pwv") != password_fingerprint(user.hashed_password)
            or payload.get("mfv", 0) != mfa.version_of(mfa_row)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid. Please login again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    # Idle timeout: a session unused for SESSION_IDLE_TIMEOUT_MINUTES is ended
    # (its token revoked); otherwise the use is noted (app/core/sessions.py).
    touch_session(db, payload, user.id)

    # A password someone else chose must be replaced before anything else.
    # (request is None only when code calls this function directly, never for
    # an HTTP route.)
    if user.must_change_password and request is not None and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required: choose your own password before continuing.",
            headers={"X-Password-Change-Required": "1"},
        )

    # Two-step sign-in required for this role and not set up yet (past the grace period, or a
    # system administrator): only the setup itself (app/core/mfa.py).
    if (request is not None and request.url.path not in mfa.ENROLMENT_ALLOWED
            and not (mfa_row is not None and mfa_row.enabled)
            and mfa.enrolment_due(mfa.get_policy(db), user, mfa_row)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Two-step sign-in required: set it up before continuing.",
            headers={"X-MFA-Enrollment-Required": "1"},
        )

    # Disk nearly full: only system administrators may change anything (app/core/storage_guard.py).
    check_storage(request, user)

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Require admin role for accessing the endpoint.

    Args:
        current_user: Authenticated user from get_current_user dependency

    Returns:
        User: The user if they have admin role

    Raises:
        HTTPException: 403 if user is not admin
    """
    # FIXED: Use .value for consistent enum comparison
    if current_user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_admin_or_manager(current_user: User = Depends(get_current_user)) -> User:
    """
    Require admin or manager role for accessing the endpoint.

    Args:
        current_user: Authenticated user from get_current_user dependency

    Returns:
        User: The user if they have admin or manager role

    Raises:
        HTTPException: 403 if user is neither admin nor manager
    """
    if current_user.role.value not in ["admin", "manager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or manager role required"
        )
    return current_user


def assert_session_access(session, current_user: User):
    """
    Enforce object-level ownership on an audit session.

    Admins may access any session; every other user may only access sessions
    they own. Raises 404 (not 403) when the session is missing or owned by
    someone else, so the existence of other users' sessions is not leaked.

    Args:
        session: AuditSession instance (or None) already fetched by the caller
        current_user: Authenticated user

    Returns:
        The session, when access is allowed.

    Raises:
        HTTPException: 404 if the session is missing or not owned by the user
    """
    if session is None or (
        current_user.role.value != "admin"
        and getattr(session, "user_id", None) != current_user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit session not found",
        )
    return session


def require_own_session(db: Session, session_id: Optional[int], current_user: User):
    """Load an audit session a request refers to and enforce ownership
    (assert_session_access: 404 for a missing or someone else's session).
    None when the request names no session."""
    if session_id is None:
        return None
    from app.models.audit import AuditSession
    session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
    return assert_session_access(session, current_user)


def require_own_result(db: Session, result_id: Optional[int], current_user: User):
    """Load an audit result a request refers to and enforce ownership of its
    session: a hardening request may only act on findings of the caller's own
    audits (admins: any). 404 for a missing or someone else's result."""
    if result_id is None:
        return None
    from app.models.audit import AuditResult
    result = db.query(AuditResult).filter(AuditResult.id == result_id).first()
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit result not found")
    assert_session_access(result.session, current_user)
    return result


def require_own_action(db: Session, action_id: int, current_user: User):
    """Load a hardening action and enforce that the caller created it (admins:
    any). 404 for a missing or someone else's action."""
    from app.models.hardening import HardeningAction
    action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first()
    if action is None or (current_user.role.value != "admin" and action.user_id != current_user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardening action not found")
    return action


def owned_sessions(query, owner_id: Optional[int]):
    """Restrict an AuditSession query to one owner (``owner_id`` from
    owner_scope); None leaves it unrestricted (admins). Every audit session
    listing, count, history and statistic goes through this."""
    if owner_id is None:
        return query
    from app.models.audit import AuditSession
    return query.filter(AuditSession.user_id == owner_id)


def owner_scope(current_user: User) -> Optional[int]:
    """
    The user id a *list* query must be filtered by, or None for admins.

    The list endpoints are the other half of assert_session_access: without this
    filter a non-admin could not open someone else's session but could still
    enumerate them (target IPs, job names, compliance scores) from the listing.
    """
    if current_user.role.value == "admin":
        return None
    return current_user.id


def require_permission(module: str, permission_type: str):
    """
    Factory function to create a dependency that checks if user has specific permission.

    Args:
        module: Module name (e.g., "ASSET_LIST", "DASHBOARD")
        permission_type: Permission type ("read", "write", "delete")

    Returns:
        Dependency function that checks permission
    """
    def check_permission(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        """The dependency itself: admins pass, everyone else needs the module's permission row with the
        requested flag set; otherwise 403.
        """
        from app.models import UserPermission

        # Admin always has all permissions
        if current_user.role.value == "admin":
            return current_user

        # Check user's permission for this module
        permission = db.query(UserPermission).filter(
            UserPermission.user_id == current_user.id,
            UserPermission.module == module
        ).first()

        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"No permission for {module}"
            )

        # Check specific permission type
        has_permission = False
        if permission_type == "read" and permission.can_read:
            has_permission = True
        elif permission_type == "write" and permission.can_write:
            has_permission = True
        elif permission_type == "delete" and permission.can_delete:
            has_permission = True

        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permission: {permission_type} access required for {module}"
            )

        return current_user

    # What this dependency checks, readable from the route (tests audit every
    # route with it); works the same whether this module runs as source or
    # compiled, where a closure's cells are not inspectable.
    check_permission.permission = (module, permission_type)
    return check_permission
