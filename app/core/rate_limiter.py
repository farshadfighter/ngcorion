"""
Rate Limiter for Discovery Scans

Prevents abuse and DoS attacks by limiting the number of concurrent
and hourly scans per user.
"""

from datetime import datetime, timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.discovery import DiscoveryScan


class RateLimiter:
    """
    Rate limiting service for discovery scans

    Implements two limits:
    1. Max concurrent scans per user (prevents resource exhaustion)
    2. Max scans per hour per user (prevents API abuse)
    """

    # Configuration
    MAX_CONCURRENT_SCANS = 5
    MAX_SCANS_PER_HOUR = 20

    @staticmethod
    def check_scan_limit(user_id: int, db: Session) -> bool:
        """
        Check if user can start a new scan

        Raises HTTPException if limits exceeded.
        Returns True if user can proceed.

        Args:
            user_id: User attempting to start scan
            db: Database session

        Returns:
            bool: True if allowed

        Raises:
            HTTPException: 429 if rate limit exceeded
        """
        # Check concurrent scan limit
        running_scans = db.query(DiscoveryScan).filter(
            DiscoveryScan.user_id == user_id,
            DiscoveryScan.status == "running"
        ).count()

        if running_scans >= RateLimiter.MAX_CONCURRENT_SCANS:
            raise HTTPException(
                status_code=429,
                detail=f"Maximum concurrent scans ({RateLimiter.MAX_CONCURRENT_SCANS}) reached. "
                       f"Please wait for existing scans to complete."
            )

        # Check hourly scan limit
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_scans = db.query(DiscoveryScan).filter(
            DiscoveryScan.user_id == user_id,
            DiscoveryScan.started_at > one_hour_ago
        ).count()

        if recent_scans >= RateLimiter.MAX_SCANS_PER_HOUR:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({RateLimiter.MAX_SCANS_PER_HOUR} scans per hour). "
                       f"Please try again later."
            )

        return True

    @staticmethod
    def get_user_scan_stats(user_id: int, db: Session) -> dict:
        """
        Get current scan statistics for a user

        Useful for displaying to user how close they are to limits.

        Args:
            user_id: User ID
            db: Database session

        Returns:
            dict: Statistics including concurrent and hourly counts
        """
        # Concurrent scans
        running_scans = db.query(DiscoveryScan).filter(
            DiscoveryScan.user_id == user_id,
            DiscoveryScan.status == "running"
        ).count()

        # Hourly scans
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_scans = db.query(DiscoveryScan).filter(
            DiscoveryScan.user_id == user_id,
            DiscoveryScan.started_at > one_hour_ago
        ).count()

        return {
            "concurrent_scans": running_scans,
            "concurrent_limit": RateLimiter.MAX_CONCURRENT_SCANS,
            "concurrent_available": RateLimiter.MAX_CONCURRENT_SCANS - running_scans,
            "scans_last_hour": recent_scans,
            "hourly_limit": RateLimiter.MAX_SCANS_PER_HOUR,
            "hourly_available": RateLimiter.MAX_SCANS_PER_HOUR - recent_scans
        }
