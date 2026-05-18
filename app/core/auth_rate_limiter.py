"""
Rate limiter for /auth/login.

Counts recent failed login attempts in the LoginLog table and rejects further
attempts from an IP or for a username once thresholds are exceeded.
"""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import LoginLog


WINDOW_MINUTES = 15
MAX_FAILURES_PER_IP = 5
MAX_FAILURES_PER_USERNAME = 10


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
