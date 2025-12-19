"""
Password hashing, JWT token generation, and authentication utilities.

Provides secure password hashing using bcrypt and JWT token management
for user authentication.

NOTE: For user authentication dependency, use `get_current_user` from
`app.core.dependencies` instead.
"""
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext

from .config import settings

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
    exceeds this limit, an error is raised.

    Args:
        password: The plain text password to hash

    Returns:
        str: The bcrypt hash of the password

    Raises:
        ValueError: If password exceeds 72 bytes (bcrypt limitation)
    """
    # Check bcrypt 72-byte limitation
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        raise ValueError(
            f"Password is too long ({len(password_bytes)} bytes). "
            f"Maximum allowed is 72 bytes (bcrypt limitation). "
            f"Please use a shorter password."
        )

    return pwd_context.hash(password)


def create_access_token(data: dict) -> str:
    """
    Create a JWT access token.

    Args:
        data: Dictionary containing token payload (e.g., {"sub": username, "role": role})

    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt