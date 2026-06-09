"""
Auth Schemas - Login and Token schemas
"""
from pydantic import BaseModel, EmailStr, field_validator
from typing import Dict

from app.schemas.user import validate_password_strength


class UserLogin(BaseModel):
    """Login request schema"""
    username: str
    password: str


class ForgotPasswordRequest(BaseModel):
    """Request a password-reset link for the account with this email."""
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Set a new password using a reset token from the email link."""
    token: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def _validate_password(cls, v: str) -> str:
        return validate_password_strength(v)


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str


class PermissionDetail(BaseModel):
    """Permission detail for a single module"""
    read: bool
    write: bool
    delete: bool


class Token(BaseModel):
    """
    Login response schema
    
    Example response:
    {
        "access_token": "eyJhbGciOiJIUzI1NiIs...",
        "token_type": "bearer",
        "username": "admin",
        "role": "admin",
        "permissions": {
            "dashboard": {"read": true, "write": true, "delete": true},
            "asset_list": {"read": true, "write": true, "delete": true},
            ...
        }
    }
    """
    access_token: str
    token_type: str
    username: str
    role: str
    permissions: Dict[str, PermissionDetail]


class TokenData(BaseModel):
    """Schema for JWT token payload (internal use)"""
    username: str | None = None
    role: str | None = None