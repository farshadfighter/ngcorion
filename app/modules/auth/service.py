"""
Auth Service - Authentication Logic

Handles user authentication and validation.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import User, PasswordResetToken
from app.core.security import verify_password, get_password_hash
from app.core.config import settings


def _hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest used to store/look up a reset token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


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

    def create_password_reset_token(self, email: str, ip_address: str = None):
        """
        Create a one-time password-reset token for the active account with this email.

        Returns:
            (raw_token, user) if an active account exists, else None.
            The caller must email the raw token and otherwise treat a None result
            identically to a success (to avoid leaking whether the email exists).
        """
        user = self.db.query(User).filter(User.email == email).first()
        if not user or not user.is_active:
            return None

        # Invalidate the user's previous unused tokens so only the newest link works.
        now = datetime.now(timezone.utc)
        self.db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)

        raw_token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=_hash_token(raw_token),
            expires_at=expires_at,
            ip_address=ip_address,
        )
        self.db.add(reset_token)
        self.db.commit()

        return raw_token, user

    def reset_password_with_token(self, raw_token: str, new_password: str):
        """
        Consume a reset token and set the user's new password.

        Returns the User on success, or None if the token is unknown, already
        used, or expired.
        """
        token_hash = _hash_token(raw_token)
        now = datetime.now(timezone.utc)

        reset_token = self.db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        ).first()

        if not reset_token:
            return None

        user = self.db.query(User).filter(User.id == reset_token.user_id).first()
        if not user:
            return None

        user.hashed_password = get_password_hash(new_password)
        reset_token.used_at = now
        self.db.commit()

        return user