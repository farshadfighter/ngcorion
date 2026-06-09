"""
Rate limiter for /auth/login.

Counts recent failed login attempts in the LoginLog table and rejects further
attempts from an IP or for a username once thresholds are exceeded.
"""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import LoginLog, PasswordResetToken, User


WINDOW_MINUTES = 15
MAX_FAILURES_PER_IP = 5
MAX_FAILURES_PER_USERNAME = 10

# Password-reset request limits (counts reset tokens created in the window).
RESET_WINDOW_MINUTES = 15
MAX_RESET_REQUESTS_PER_IP = 5
MAX_RESET_REQUESTS_PER_EMAIL = 3


def check_login_rate_limit(db: Session, ip_address: str, username: str) -> None:
    """Raise HTTP 429 when recent failed-login thresholds are exceeded."""
    window_start = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)

    base = db.query(LoginLog).filter(
        LoginLog.success.is_(False),
        LoginLog.timestamp >= window_start,
    )

    if ip_address:
        ip_failures = base.filter(LoginLog.ip_address == ip_address).count()
        if ip_failures >= MAX_FAILURES_PER_IP:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many failed login attempts from this IP. "
                    f"Try again in {WINDOW_MINUTES} minutes."
                ),
            )

    if username:
        user_failures = base.filter(LoginLog.username == username).count()
        if user_failures >= MAX_FAILURES_PER_USERNAME:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many failed login attempts for this account. "
                    f"Try again in {WINDOW_MINUTES} minutes."
                ),
            )


def check_password_reset_rate_limit(db: Session, ip_address: str, email: str) -> None:
    """Raise HTTP 429 when too many reset requests come from an IP or for an email.

    Counts password-reset tokens created in the recent window. This runs before a
    token is created, so it caps how often the forgot-password endpoint can be used
    regardless of whether the target email exists.
    """
    window_start = datetime.now(timezone.utc) - timedelta(minutes=RESET_WINDOW_MINUTES)

    base = db.query(PasswordResetToken).filter(
        PasswordResetToken.created_at >= window_start,
    )

    if ip_address:
        ip_requests = base.filter(PasswordResetToken.ip_address == ip_address).count()
        if ip_requests >= MAX_RESET_REQUESTS_PER_IP:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many password reset requests from this IP. "
                    f"Try again in {RESET_WINDOW_MINUTES} minutes."
                ),
            )

    if email:
        email_requests = base.join(User, PasswordResetToken.user_id == User.id).filter(
            User.email == email,
        ).count()
        if email_requests >= MAX_RESET_REQUESTS_PER_EMAIL:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many password reset requests for this account. "
                    f"Try again in {RESET_WINDOW_MINUTES} minutes."
                ),
            )
