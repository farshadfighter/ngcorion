"""
User Schemas with Permission Support
"""
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional, List


# ====================================
# Permission Schemas
# ====================================

class PermissionBase(BaseModel):
    """Base schema for a single permission"""
    module: str = Field(..., description="Module name (e.g., dashboard, asset_list)")
    can_read: bool = Field(default=False, description="Can view/read data")
    can_write: bool = Field(default=False, description="Can create/edit data")
    can_delete: bool = Field(default=False, description="Can delete data")


class PermissionCreate(PermissionBase):
    """Schema for creating permission"""
    pass


class PermissionResponse(PermissionBase):
    """Schema for permission response"""
    id: int
    
    class Config:
        from_attributes = True


# ====================================
# User Schemas
# ====================================

class UserBase(BaseModel):
    """Base user schema"""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")


class UserCreate(UserBase):
    """
    Schema for creating new user
    
    Admin must specify permissions when creating user.
    Default permissions (dashboard and asset_list read) are applied
    if not explicitly provided.
    """
    password: str = Field(..., min_length=4, max_length=72, description="Password")
    role: str = Field(default="user", description="User role: admin, manager, user, guest")
    is_active: bool = Field(default=True, description="Active status")
    permissions: Optional[List[PermissionCreate]] = Field(
        default=None, 
        description="List of permissions. If not provided, defaults will be applied."
    )


class UserUpdate(BaseModel):
    """
    Schema for updating user
    
    All fields are optional.
    """
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=4, max_length=72)
    current_password: Optional[str] = Field(
        None,
        min_length=1,
        max_length=72,
        description="Required when the authenticated user changes their own password"
    )
    role: Optional[str] = None
    is_active: Optional[bool] = None
    permissions: Optional[List[PermissionCreate]] = Field(
        default=None,
        description="Update permissions. If provided, replaces all existing permissions."
    )


class UserResponse(BaseModel):
    """
    Schema for user response with permissions
    """
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    permissions: List[PermissionResponse] = []

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """
    Schema for user list (without permissions for performance)
    """
    id: int
    username: str
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


# ====================================
# Available Modules (for frontend)
# ====================================

class ModuleInfo(BaseModel):
    """Information about available modules"""
    name: str
    description: str


def get_available_modules() -> List[ModuleInfo]:
    """
    Returns list of all available modules with descriptions.
    Useful for frontend to show module options.
    """
    return [
        ModuleInfo(name="dashboard", description="Main Dashboard"),
        ModuleInfo(name="asset_requirement", description="Asset Requirement Form"),
        ModuleInfo(name="asset_list", description="Asset List View"),
        ModuleInfo(name="asset_auto_discovery", description="Asset Auto Discovery"),
        ModuleInfo(name="user_management", description="User Management"),
        ModuleInfo(name="auditing", description="Auditing Module"),
        ModuleInfo(name="hardening", description="Hardening Module"),
        ModuleInfo(name="logs", description="System Logs"),
    ]
