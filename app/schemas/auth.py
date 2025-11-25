"""
Auth Schemas - Login and Token schemas
"""
from pydantic import BaseModel
from typing import Dict


class UserLogin(BaseModel):
    """Login request schema"""
    username: str
    password: str


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