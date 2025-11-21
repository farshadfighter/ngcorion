"""
Users Router - User management API
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.schemas.user import UserCreate, UserUpdate, UserResponse, UserListResponse
from .service import UserService

router = APIRouter()


@router.get("/", response_model=List[UserListResponse])
def get_all_users(
    db: Session = Depends(get_db)
):
    """
    Get Users list
    
    Returns:
    Users with information
    """
    service = UserService(db)
    users = service.get_all_users()
    return users


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    """
    get user data complete
    
    - **user_id**: User ID
    """
    service = UserService(db)
    user = service.get_user_by_id(user_id)
    return user


@router.post("/", response_model=UserResponse, status_code=201)
def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """
    Create new user
    
    - **username**: Username (50 - 3،unique)
    - **email**: email (unique)
    - **password**: password (4 character min)
    - **role**: User Role (admin, manager, user, guest)
    - **is_active**: activity status (defualt: true)
    """
    service = UserService(db)
    new_user = service.create_user(user_data)
    return new_user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db)
):
    """
   Edit User
    
    - **user_id**: user ID
    - All field is unnecessary(Submit only the fields you want to change.)
    """
    service = UserService(db)
    updated_user = service.update_user(user_id, user_data)
    return updated_user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    """
    Remove User
    
    - **user_id**: user ID
    
    Note: This operation is irreversible!
    """
    service = UserService(db)
    result = service.delete_user(user_id)
    return result


@router.get("/search/", response_model=List[UserListResponse])
def search_users(
    q: str = Query(..., min_length=2, description="searh description(At least two characters)"),
    db: Session = Depends(get_db)
):
    """
    Search Users
    
    - **q**: search description username or email
    
    Example : `/api/users/search/?q=admin`
    """
    service = UserService(db)
    users = service.search_users(q)
    return users