"""
Rate Limiter for Audit and Hardening Operations

Prevents resource exhaustion and API abuse for security auditing operations.
"""

from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import AuditSession

class AuditRateLimiter:

    # Configuration - can be overridden via environment variables
    MAX_CONCURRENT_AUDITS = 5  # Max concurrent audit operations per user
    MAX_AUDITS_PER_HOUR = 20   # Max audits per hour per user
    MAX_AUDITS_PER_DAY = 100   # Max audits per day per user

    @staticmethod
    def check_audit_limit(user_id: int, db: Session) -> bool:
        """
        Check if user can start a new audit operation

        Raises HTTPException if limits exceeded.
        Returns True if user can proceed.

        Args:
            user_id: User attempting to start audit
            db: Database session

        Returns:
            bool: True if allowed

        Raises:
            HTTPException: 429 if rate limit exceeded
        """
        # Check concurrent audit limit
        running_audits = db.query(AuditSession).filter(
            AuditSession.user_id == user_id,
            AuditSession.status == "running"
        ).count()

        if running_audits >= AuditRateLimiter.MAX_CONCURRENT_AUDITS:
            raise HTTPException(
                status_code=429,
                detail=f"Maximum concurrent audits ({AuditRateLimiter.MAX_CONCURRENT_AUDITS}) reached. "
                       f"Please wait for existing audits to complete."
            )

        # Check hourly audit limit
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_audits = db.query(AuditSession).filter(
            AuditSession.user_id == user_id,
            AuditSession.started_at > one_hour_ago
        ).count()

        if recent_audits >= AuditRateLimiter.MAX_AUDITS_PER_HOUR:
            raise HTTPException(
                status_code=429,
                detail=f"Hourly rate limit exceeded ({AuditRateLimiter.MAX_AUDITS_PER_HOUR} audits per hour). "
                       f"Please try again later."
            )

        # Check daily audit limit
        one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
        daily_audits = db.query(AuditSession).filter(
            AuditSession.user_id == user_id,
            AuditSession.started_at > one_day_ago
        ).count()

        if daily_audits >= AuditRateLimiter.MAX_AUDITS_PER_DAY:
            raise HTTPException(
                status_code=429,
                detail=f"Daily rate limit exceeded ({AuditRateLimiter.MAX_AUDITS_PER_DAY} audits per day). "
                       f"Quota will reset in {24 - (datetime.now(timezone.utc) - one_day_ago).seconds // 3600} hours."
            )

        return True

    @staticmethod
    def get_user_audit_stats(user_id: int, db: Session) -> dict:
        """
        Get current audit statistics for a user

        Useful for displaying to user how close they are to limits.

        Args:
            user_id: User ID
            db: Database session

        Returns:
            dict: Statistics including concurrent, hourly, and daily counts
        """
        now = datetime.now(timezone.utc)

        # Concurrent audits
        running_audits = db.query(AuditSession).filter(
            AuditSession.user_id == user_id,
            AuditSession.status == "running"
        ).count()

        # Hourly audits
        one_hour_ago = now - timedelta(hours=1)
        hourly_audits = db.query(AuditSession).filter(
            AuditSession.user_id == user_id,
            AuditSession.started_at > one_hour_ago
        ).count()

        # Daily audits
        one_day_ago = now - timedelta(days=1)
        daily_audits = db.query(AuditSession).filter(
            AuditSession.user_id == user_id,
            AuditSession.started_at > one_day_ago
        ).count()

        return {
            "concurrent_audits": running_audits,
            "concurrent_limit": AuditRateLimiter.MAX_CONCURRENT_AUDITS,
            "concurrent_available": max(0, AuditRateLimiter.MAX_CONCURRENT_AUDITS - running_audits),

            "audits_last_hour": hourly_audits,
            "hourly_limit": AuditRateLimiter.MAX_AUDITS_PER_HOUR,
            "hourly_available": max(0, AuditRateLimiter.MAX_AUDITS_PER_HOUR - hourly_audits),

            "audits_last_day": daily_audits,
            "daily_limit": AuditRateLimiter.MAX_AUDITS_PER_DAY,
            "daily_available": max(0, AuditRateLimiter.MAX_AUDITS_PER_DAY - daily_audits)
        }

    @classmethod
    def configure(cls, concurrent: int = None, hourly: int = None, daily: int = None):
        """
        Configure rate limits (useful for testing or environment-specific settings)

        Args:
            concurrent: Max concurrent audits (default: 5)
            hourly: Max audits per hour (default: 20)
            daily: Max audits per day (default: 100)
        """
        if concurrent is not None:
            cls.MAX_CONCURRENT_AUDITS = concurrent
        if hourly is not None:
            cls.MAX_AUDITS_PER_HOUR = hourly
        if daily is not None:
            cls.MAX_AUDITS_PER_DAY = daily
