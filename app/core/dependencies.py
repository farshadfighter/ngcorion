"""
Dependencies for authentication and authorization.

Provides FastAPI dependency functions for:
- JWT token validation
- User authentication
- Role-based access control
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, ExpiredSignatureError, jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models import User

security = HTTPBearer()


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
