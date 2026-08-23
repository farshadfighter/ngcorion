"""
Dependencies for authentication and authorization.

Provides FastAPI dependency functions for:
- JWT token validation
- User authentication
- Role-based access control
- License quota enforcement
"""
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, ExpiredSignatureError, jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.license_client import LicenseServerError, LicenseServerUnreachable
from app.models import User

import logging
import requests

logger = logging.getLogger(__name__)

security = HTTPBearer()


def license_error_detail(exc: requests.HTTPError, fallback: str) -> str:
    """
    Pull the license server's own error message out of an HTTPError.

    The body is not guaranteed to be JSON (a proxy or a crashed worker can send
    HTML), and calling .json() on it raised a JSONDecodeError *inside* the
    exception handler — turning an actionable "quota exhausted" into an opaque
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


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
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
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

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

    return check_permission


def require_quota(operation_type: str, count: int = 1):
    """
    Dependency that consumes a license quota slot before the endpoint runs.
    Raises HTTP 403 if quota exhausted.
    
    WARNING: This consumes quota BEFORE the operation runs.
    If the operation fails, quota is already consumed.
    Use consume_quota_on_success() for operations that might fail.

    Args:
        operation_type: One of "audit", "harden" (Asset Management is not
            license-gated)
        count: Number of operations to consume (default: 1)
    
    Usage:
        @router.post("/execute", dependencies=[Depends(require_quota("audit"))])
        def execute_audit(...):
            ...
    """
    def check(request: Request, current_user: User = Depends(get_current_user)) -> None:
        from app.core.license_state import update_usage
        
        client = request.app.state.license_client
        try:
            result = client.consume(operation_type, count)
            # Optimistic update of local usage counter
            update_usage(operation_type, count)
        except LicenseServerError as e:
            # The license server answered, but with a 5xx/429 — it is broken or
            # overloaded, not saying anything about this license.
            logger.error(f"[License] consume({operation_type}) failed: {e}")
            raise HTTPException(
                status_code=503,
                detail=(
                    f"License server returned HTTP {e.status_code}, so this "
                    f"operation cannot be authorized right now. No quota was "
                    f"consumed. Please retry shortly."
                ),
                headers={"X-License-Server-Unreachable": "true", "Retry-After": "30"},
            )
        except LicenseServerUnreachable as e:
            # Network-level failure (already retried by the client). Report it as
            # a temporary infrastructure problem, not as a licensing verdict.
            logger.warning(f"[License] consume({operation_type}) failed: {e}")
            raise HTTPException(
                status_code=503,
                detail=(
                    "License server is unreachable, so this operation cannot be "
                    "authorized right now. Please retry once connectivity is restored."
                ),
                headers={"X-License-Server-Unreachable": "true", "Retry-After": "30"},
            )
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 400:
                detail = license_error_detail(e, "Quota exhausted")
                logger.warning(
                    f"[License] consume({operation_type}) refused by the "
                    f"license server: {detail}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=detail,
                    headers={"X-Quota-Exhausted": "true"}
                )
            status_code = e.response.status_code if e.response is not None else "unknown"
            detail = license_error_detail(
                e, f"License server returned an error (HTTP {status_code})"
            )
            logger.error(f"[License] consume({operation_type}) HTTP {status_code}: {detail}")
            raise HTTPException(status_code=503, detail=detail)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"[License] consume({operation_type}) failed unexpectedly")
            raise HTTPException(
                status_code=503,
                detail=f"License check failed ({type(e).__name__}): {e}",
            )
    
    return check


def consume_quota_on_success(operation_type: str, count: int = 1):
    """
    Returns a function to consume quota AFTER successful operation.
    Use this for operations that might fail (audit, hardening).
    
    Usage:
        @router.post("/execute")
        def execute_audit(request: Request, ...):
            consume_quota = consume_quota_on_success("audit")
            
            try:
                # Do the operation
                result = perform_audit(...)
                
                # Only consume if successful
                consume_quota(request)
                
                return result
            except Exception as e:
                # Quota NOT consumed on failure
                raise
    
    Args:
        operation_type: One of "audit", "harden" (Asset Management is not
            license-gated)
        count: Number of operations to consume (default: 1)

    Returns:
        Function that consumes quota when called
    """
    def consume(request: Request) -> None:
        from app.core.license_state import update_usage
        
        client = request.app.state.license_client
        try:
            result = client.consume(operation_type, count)
            # Optimistic update of local usage counter
            update_usage(operation_type, count)
        except LicenseServerError as e:
            # The license server answered, but with a 5xx/429 — it is broken or
            # overloaded, not saying anything about this license.
            logger.error(f"[License] consume({operation_type}) failed: {e}")
            raise HTTPException(
                status_code=503,
                detail=(
                    f"License server returned HTTP {e.status_code}, so this "
                    f"operation cannot be authorized right now. No quota was "
                    f"consumed. Please retry shortly."
                ),
                headers={"X-License-Server-Unreachable": "true", "Retry-After": "30"},
            )
        except LicenseServerUnreachable as e:
            # Network-level failure (already retried by the client). Report it as
            # a temporary infrastructure problem, not as a licensing verdict.
            logger.warning(f"[License] consume({operation_type}) failed: {e}")
            raise HTTPException(
                status_code=503,
                detail=(
                    "License server is unreachable, so this operation cannot be "
                    "authorized right now. Please retry once connectivity is restored."
                ),
                headers={"X-License-Server-Unreachable": "true", "Retry-After": "30"},
            )
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 400:
                detail = license_error_detail(e, "Quota exhausted")
                logger.warning(
                    f"[License] consume({operation_type}) refused by the "
                    f"license server: {detail}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=detail,
                    headers={"X-Quota-Exhausted": "true"}
                )
            status_code = e.response.status_code if e.response is not None else "unknown"
            detail = license_error_detail(
                e, f"License server returned an error (HTTP {status_code})"
            )
            logger.error(f"[License] consume({operation_type}) HTTP {status_code}: {detail}")
            raise HTTPException(status_code=503, detail=detail)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"[License] consume({operation_type}) failed unexpectedly")
            raise HTTPException(
                status_code=503,
                detail=f"License check failed ({type(e).__name__}): {e}",
            )
    
    return consume


def check_quota_available(operation_type: str, count: int = 1):
    """
    Dependency that ONLY CHECKS if quota is available, does NOT consume it.
    Use this with consume_quota_on_success() for operations that might fail.
    
    Usage:
        @router.post("/execute", dependencies=[Depends(check_quota_available("audit"))])
        def execute_audit(request: Request, ...):
            consume_quota = consume_quota_on_success("audit")
            
            try:
                result = perform_audit(...)
                consume_quota(request)  # Only consume on success
                return result
            except Exception:
                raise  # Quota not consumed
    
    Args:
        operation_type: One of "audit", "harden" (Asset Management is not
            license-gated)
        count: Number of operations to check (default: 1)

    Returns:
        Dependency function that checks quota availability
    """
    def check(request: Request, current_user: User = Depends(get_current_user)) -> None:
        from app.core.license_state import get_license_state

        state = get_license_state()
        if not state.valid or state.limits is None:
            return  # License middleware should have caught this

        # Map operation type to limit/usage fields
        operation_map = {
            "audit": ("max_audits", "used_audits"),
            "harden": ("max_hardens", "used_hardens"),
        }
        
        if operation_type not in operation_map:
            return
        
        max_field, used_field = operation_map[operation_type]
        max_value = state.limits.get(max_field)
        
        if max_value is None:
            return  # Unlimited plan
        
        used_value = state.usage.get(used_field, 0) if state.usage else 0
        
        if used_value + count > max_value:
            raise HTTPException(
                status_code=403,
                detail=f"{operation_type.capitalize()} quota exhausted ({used_value}/{max_value}). Upgrade your plan.",
                headers={"X-Quota-Exhausted": "true"}
            )
    
    return check
