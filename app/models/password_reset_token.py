"""
Password Reset Token Model

Stores one-time, time-limited OTP codes used by the "forgot password" flow.

Security notes:
- Only the SHA-256 hash of the OTP is stored here, never the raw code.
- Codes are single-use (``used_at``), expire (``expires_at``), and are
  guess-limited (``attempts``).
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SHA-256 hex digest of the OTP code; the raw code is only ever emailed.
    token_hash = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    # Number of failed verification attempts; the code is invalidated past the limit.
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    ip_address = Column(String, nullable=True)

    user = relationship("User")
