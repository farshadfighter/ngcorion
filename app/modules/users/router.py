"""
Users Router - User management API with Permission Control
"""
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, UserRole
from app.models.user_permission import ModuleEnum, get_all_modules
from app.schemas.user import (
    UserCreate, UserUpdate, UserResponse, 
    UserListResponse, ModuleInfo, get_available_modules
)
from .service import UserService

router = APIRouter()


# ==========================================
# Permission Check Helper
# ==========================================

def check_user_management_permission(current_user: User, action: str, db: Session):
    """
    Check if current user can perform action on user_management module
    
    Admin: Always allowed
    Others: Check permission table
    """
    # Admin has all permissions
    if current_user.role == UserRole.ADMIN:
        return True
    
    service = UserService(db)
    has_permission = service.check_permission(
        user_id=current_user.id,
        module="user_management",
        action=action
    )
    
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You don't have {action} permission for user management"
        )
    
    return True


# ==========================================
# Module Info Endpoints (Public for authenticated users)
# ==========================================

@router.get("/modules", response_model=List[ModuleInfo])
def get_modules(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of all available modules
    
    Used by frontend to show module options when creating/editing users.
    Any authenticated user can see this list.
    """
    return get_available_modules()


# ==========================================
# User CRUD Endpoints
# ==========================================

@router.get("/", response_model=List[UserListResponse])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all users list
    
    Requires: user_management.read permission (or admin role)
    
    Returns: List of users (without permissions for performance)
    """
    check_user_management_permission(current_user, "read", db)
    
    service = UserService(db)
    users = service.get_all_users()
    return users


@router.get("/search/", response_model=List[UserListResponse])
def search_users(
    q: str = Query(..., min_length=2, description="Search query (at least 2 characters)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Search users by username or email
    
    Requires: user_management.read permission (or admin role)
    
    - **q**: Search query for username or email
    
    Example: `/api/users/search/?q=admin`
    """
    check_user_management_permission(current_user, "read", db)
    
    service = UserService(db)
    users = service.search_users(q)
    return users


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get user details with permissions
    
    Requires: user_management.read permission (or admin role)
    
    - **user_id**: User ID
    
    Returns: User with full permission details
    """
    check_user_management_permission(current_user, "read", db)
    
    service = UserService(db)
    user = service.get_user_by_id(user_id)
    return user


@router.post("/", response_model=UserResponse, status_code=201)
def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create new user with permissions
    
    Requires: user_management.write permission (or admin role)
    
    - **username**: Username (3-50 characters, unique)
    - **email**: Email address (unique)
    - **password**: Password (minimum 4 characters)
    - **role**: User role (admin, manager, user, guest)
    - **is_active**: Activity status (default: true)
    - **permissions**: List of module permissions (optional)
    
    If permissions not provided, defaults are applied:
    - dashboard: read=True
    - asset_list: read=True
    - all others: False
    
    Note: Admin users don't need permissions (they have all access)
    """
    check_user_management_permission(current_user, "write", db)
    
    service = UserService(db)
    new_user = service.create_user(user_data)
    return new_user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update user information and permissions
    
    Requires: user_management.write permission (or admin role)
    
    - **user_id**: User ID
    - All fields are optional (submit only fields you want to change)
    - **permissions**: If provided, replaces ALL existing permissions
    
    Note: Cannot change admin user's permissions (they always have full access)
    """
    check_user_management_permission(current_user, "write", db)
    
    service = UserService(db)
    updated_user = service.update_user(user_id, user_data)
    return updated_user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete user

    Requires: user_management.delete permission (or admin role)

    - **user_id**: User ID

    Note: This operation is irreversible! User's permissions are also deleted.

    Warning: Cannot delete yourself or the last admin user.
    """
    check_user_management_permission(current_user, "delete", db)

    service = UserService(db)
    result = service.delete_user(user_id, current_user_id=current_user.id)
    return result