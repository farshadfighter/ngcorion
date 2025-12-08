"""
Auth Service - Authentication Logic

Handles user authentication and validation.
"""
from sqlalchemy.orm import Session
from app.models import User
from app.core.security import verify_password


class AuthService:
    """Authentication service for user login validation."""

    def __init__(self, db: Session):
        """
        Initialize authentication service.
        """
        self.db = db

    def authenticate_user(self, username: str, password: str):
        """
        Authenticate a user with username and password.

        Args:
            username: The username to authenticate
            password: The plain text password to verify

        Returns:
            User: User object if authentication succeeds
            False: If username not found or password doesn't match
        """
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user