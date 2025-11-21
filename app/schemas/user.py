"""
Schemas مربوط به کاربر
"""
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional


class UserBase(BaseModel):
    """Schema پایه کاربر"""
    username: str = Field(..., min_length=3, max_length=50, description="نام کاربری")
    email: EmailStr = Field(..., description="ایمیل")


class UserCreate(UserBase):
    """
    Schema برای ساخت کاربر جدید
    
    استفاده: POST /api/users/create
    """
    password: str = Field(..., min_length=4, max_length=72, description="رمز عبور")
    role: str = Field(default="user", description="نقش کاربر: admin, manager, user, guest")
    is_active: bool = Field(default=True, description="وضعیت فعال بودن")


class UserUpdate(BaseModel):
    """
    Schema برای ویرایش کاربر
    
    استفاده: PUT /api/users/update/{user_id}
    همه فیلدها اختیاری هستند
    """
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=4, max_length=72)
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    """
    Schema برای نمایش اطلاعات کاربر
    
    استفاده: Response تمام API ها
    """
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True  # برای تبدیل از SQLAlchemy Model


class UserListResponse(BaseModel):
    """
    Schema برای لیست کاربران با اطلاعات خلاصه
    """
    id: int
    username: str
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True