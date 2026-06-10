"""
Auth Service - Authentication Logic

Handles user authentication and validation.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import User, PasswordResetToken
from app.core.security import verify_password, get_password_hash
from app.core.config import settings


def _hash_code(raw_code: str) -> str:
    """Return the SHA-256 hex digest used to store/verify an OTP code."""
    return hashlib.sha256(raw_code.encode("utf-8")).hexdigest()


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

    def create_password_reset_otp(self, email: str, ip_address: str = None):
        """
        Create a one-time numeric OTP for the active account with this email.

        Returns:
            (otp, user) if an active account exists, else None.
            The caller must email the OTP and otherwise treat a None result
            identically to a success (to avoid leaking whether the email exists).
        """
        user = self.db.query(User).filter(User.email == email).first()
        if not user or not user.is_active:
            return None

        # Invalidate the user's previous unused codes so only the newest one works.
        now = datetime.now(timezone.utc)
        self.db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)

        # 6-digit code, zero-padded (e.g. "004271").
        otp = f"{secrets.randbelow(10**6):06d}"
        expires_at = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
        reset_code = PasswordResetToken(
            user_id=user.id,
            token_hash=_hash_code(otp),
            expires_at=expires_at,
            ip_address=ip_address,
        )
        self.db.add(reset_code)
        self.db.commit()

        return otp, user

    def reset_password_with_otp(self, email: str, otp: str, new_password: str):
        """
        Verify an emailed OTP and set the user's new password.

        Returns the User on success, or None if the email/code is wrong, the code
        is expired/used, or too many wrong attempts have been made. A 6-digit code
        is brute-forceable, so verification is scoped to the user, attempt-limited,
        and uses a constant-time comparison.
        """
        now = datetime.now(timezone.utc)

        user = self.db.query(User).filter(User.email == email).first()
        if not user or not user.is_active:
            return None

        reset_code = self.db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        ).order_by(PasswordResetToken.created_at.desc()).first()

        if not reset_code:
            return None

        # Too many wrong tries already — burn the code and force a new request.
        if reset_code.attempts >= settings.PASSWORD_RESET_MAX_ATTEMPTS:
            reset_code.used_at = now
            self.db.commit()
            return None

        if not hmac.compare_digest(_hash_code(otp), reset_code.token_hash):
            reset_code.attempts += 1
            # Invalidate once the limit is reached so it can't be guessed further.
            if reset_code.attempts >= settings.PASSWORD_RESET_MAX_ATTEMPTS:
                reset_code.used_at = now
            self.db.commit()
            return None

        user.hashed_password = get_password_hash(new_password)
        reset_code.used_at = now
        self.db.commit()

        return user