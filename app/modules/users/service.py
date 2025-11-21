"""
User Service - (CRUD)
"""
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
from typing import List, Optional

from app.models import User, UserRole
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash


class UserService:
    """User management service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_all_users(self) -> List[User]:
        """
        get users list
        
        Returns:
        All users list
        """
        return self.db.query(User).all()
    
    def get_user_by_id(self, user_id: int) -> User:
        """
        get user by ID
        
        Args:
            user_id: User Identify
        
        Returns:
            User object
        
        Raises:
            HTTPException: if user not found or already taken
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"the user with {user_id} id not found"
            )
        
        return user
    
    def create_user(self, user_data: UserCreate) -> User:
        """
        Creat new User
        
        Args:
            user_data: new user data
        
        Returns:
            Created User object
        
        Raises:
            HTTPException: if email or Already available
        """
        # بررسی تکراری نبودن username
        existing_user = self.db.query(User).filter(
            User.username == user_data.username
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User name '{user_data.username}' already used."
            )
        
        # بررسی تکراری نبودن email
        existing_email = self.db.query(User).filter(
            User.email == user_data.email
        ).first()
        
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{user_data.email}' already used."
            )
        
        # تبدیل role به enum
        try:
            user_role = UserRole(user_data.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{user_data.role}' Is invalid, please use valid Role: admin, manager, user, guest"
            )
        
        # ساخت کاربر جدید
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=get_password_hash(user_data.password),
            role=user_role,
            is_active=user_data.is_active
        )
        
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)
        
        print(f"New user created successfully --->: {new_user.username} ({new_user.role.value})")
        
        return new_user
    
    def update_user(self, user_id: int, user_data: UserUpdate) -> User:
        """
        Edit user
        
        Args:
            user_id: User ID
            user_data: User data (Optinal)
        
        Returns:
            Udated User object 
        
        Raises:
            HTTPException: if user not found or Already available
        """
        # پیدا کردن کاربر
        user = self.get_user_by_id(user_id)
        
        # به‌روزرسانی username
        if user_data.username is not None:
            # بررسی تکراری نبودن
            existing = self.db.query(User).filter(
                User.username == user_data.username,
                User.id != user_id
            ).first()
            
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"user name '{user_data.username}' Already used"
                )
            
            user.username = user_data.username
        
        # به‌روزرسانی email
        if user_data.email is not None:
            existing = self.db.query(User).filter(
                User.email == user_data.email,
                User.id != user_id
            ).first()
            
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"email '{user_data.email}' Already used"
                )
            
            user.email = user_data.email
        
        # به‌روزرسانی password
        if user_data.password is not None:
            user.hashed_password = get_password_hash(user_data.password)
        
        # به‌روزرسانی role
        if user_data.role is not None:
            try:
                user.role = UserRole(user_data.role)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role '{user_data.role}' not Valid"
                )
        
        # به‌روزرسانی is_active
        if user_data.is_active is not None:
            user.is_active = user_data.is_active
        
        self.db.commit()
        self.db.refresh(user)
        
        print(f"User {user.username} Update successfully")
        
        return user
    
    def delete_user(self, user_id: int) -> dict:
        """
        Remove User
        
        Args:
            user_id: ID
        
        Returns:
            success
        
        Raises:
            HTTPException: if user not found
        """
        user = self.get_user_by_id(user_id)
        
        username = user.username
        
        self.db.delete(user)
        self.db.commit()
        
        print(f"User {username} Removed.")
        
        return {
            "success": True,
            "message": f"User '{username}' Removed successfully."
        }
    
    def search_users(self, query: str) -> List[User]:
        """
       Search user by name and email
        
        Args:
            query: search query
        
        Returns:
           Users list:
        """
        return self.db.query(User).filter(
            (User.username.ilike(f"%{query}%")) | 
            (User.email.ilike(f"%{query}%"))
        ).all()