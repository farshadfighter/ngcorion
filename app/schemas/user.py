"""
User Schemas with Permission Support
"""
import re
from pydantic import BaseModel, EmailStr, Field , field_validator
from datetime import datetime
from typing import Optional, List

from app.models.user_permission import ModuleEnum



def validate_password_strength(v: str) -> str:
    """
    Validate that a password meets the security requirements.

    Shared by UserCreate, UserUpdate and the password-reset schema so the rules
    stay consistent everywhere a password is set.
    """
    if len(v) < 8:
        raise ValueError('Password must be at least 8 characters long')
    if not re.search(r'[A-Z]', v):
        raise ValueError('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', v):
        raise ValueError('Password must contain at least one lowercase letter')
    if not re.search(r'\d', v):
        raise ValueError('Password must contain at least one digit')
    if not re.search(r'[!@#$%^&*()_+=\-[\]{};\':"\\|,.<>/?]', v):
        raise ValueError('Password must contain at least one special character')
    return v



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
    password: str = Field(..., min_length=8, max_length=72, description="Password")
    role: str = Field(default="user", description="User role: admin, manager, user, guest")
    is_active: bool = Field(default=True, description="Active status")
    permissions: Optional[List[PermissionCreate]] = Field(
        default=None, 
        description="List of permissions. If not provided, defaults will be applied."
    )
    @field_validator('password')
    @classmethod
    def _validate_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserUpdate(BaseModel):
    """
    Schema for updating user
    
    All fields are optional.
    """
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8, max_length=72)
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
    @field_validator('password')
    @classmethod
    def _validate_password(cls, v: Optional[str]) -> Optional[str]:
        """Validate password meets security requirements (only if provided)"""
        if v is None:
            return v
        return validate_password_strength(v)


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


class ModuleInfo(BaseModel):
    """Information about available modules"""
    name: str
    description: str


# Human-readable label per module. ModuleEnum below is the source of truth for
# *which* modules exist — this only supplies the wording, so a module added to
# the enum can never go missing from the User Management permission picker
# (which is how "logs" ended up unassignable and "system_config" undocumented).
MODULE_DESCRIPTIONS = {
    ModuleEnum.DASHBOARD: "Main Dashboard",
    ModuleEnum.ASSET_REQUIREMENT: "Asset Requirement Form",
    ModuleEnum.ASSET_LIST: "Asset List View",
    ModuleEnum.ASSET_AUTO_DISCOVERY: "Asset Auto Discovery",
    ModuleEnum.USER_MANAGEMENT: "User Management",
    ModuleEnum.AUDITING: "Auditing Module",
    ModuleEnum.HARDENING: "Hardening Module",
    ModuleEnum.RISK: "Risk Module",
    ModuleEnum.SYSTEM_CONFIG: "System Configuration",
    ModuleEnum.LOGS: "System Log",
}


def get_available_modules() -> List[ModuleInfo]:
    """
    Returns list of all available modules with descriptions.
    Useful for frontend to show module options.
    """
    return [
        ModuleInfo(
            name=module.value,
            description=MODULE_DESCRIPTIONS.get(module, module.value),
        )
        for module in ModuleEnum
    ]
