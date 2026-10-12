"""
Auth Schemas - Login and Token schemas
"""
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Dict, Optional

from app.schemas.user import validate_password_strength


class UserLogin(BaseModel):
    """Login request schema"""
    username: str
    password: str


class ForgotPasswordRequest(BaseModel):
    """Request a password-reset OTP for the account with this email."""
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Set a new password using the OTP code emailed to the account."""
    email: EmailStr
    otp: str = Field(..., pattern=r"^\d{6}$", description="6-digit code from the email")
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
    language: str = "en"
    language_chosen: bool = False
    # The password was chosen by someone else; the UI asks for a new one first.
    must_change_password: bool = False
    # Signed in with a recovery code: how many are left (the UI warns when few remain).
    mfa_recovery_codes_left: Optional[int] = None
    # Two-step sign-in is required for this role and not set up: the UI shows only its setup.
    mfa_enrolment_due: bool = False
    # "local" or "ldap" (Active Directory / LDAP: the password is changed there, not here).
    auth_source: str = "local"


class MfaChallenge(BaseModel):
    """Login answer when the account uses two-step sign-in: no session yet, only the token that
    POST /auth/login/mfa exchanges, with a code, for one (valid a few minutes)."""
    mfa_required: bool = True
    mfa_token: str
    username: str


class MfaLogin(BaseModel):
    """Body of POST /auth/login/mfa: a 6-digit code from the app, or a recovery code."""
    mfa_token: str = Field(..., max_length=2048)
    code: str = Field(..., min_length=6, max_length=20)


class TokenData(BaseModel):
    """Schema for JWT token payload (internal use)"""
    username: str | None = None
    role: str | None = None