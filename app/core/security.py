"""
Password hashing, JWT token generation, and authentication utilities.

Provides secure password hashing using bcrypt and JWT token management
for user authentication.
"""
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import logging

from .config import settings
from .database import get_db

from app.models.user import User

logger = logging.getLogger(__name__)

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a bcrypt hash.

    Args:
        plain_password: The plain text password to verify
        hashed_password: The bcrypt hash to verify against

    Returns:
        bool: True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    bcrypt has a maximum password length of 72 bytes. If the password
    exceeds this limit, it will be truncated with a warning logged.

    Args:
        password: The plain text password to hash

    Returns:
        str: The bcrypt hash of the password

    Raises:
        ValueError: If password exceeds 72 bytes (for security awareness)
    """
    # Check bcrypt 72-byte limitation
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        # SECURITY FIX: Raise error instead of silent truncation
        # This prevents user confusion about password requirements
        raise ValueError(
            f"Password is too long ({len(password_bytes)} bytes). "
            f"Maximum allowed is 72 bytes (bcrypt limitation). "
            f"Please use a shorter password."
        )

    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
    ):
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
# Find user in Database
    user = db.query(User).filter(User.username == user_id).first()
    
    if user is None:
        raise credentials_exception
    
# Check activity
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user