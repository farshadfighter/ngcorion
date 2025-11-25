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
    current_user: User = De