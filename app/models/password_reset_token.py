"""
Password Reset Token Model

Stores one-time, time-limited tokens used by the "forgot password" flow.

Security notes:
- Only the SHA-256 hash of the token is stored here, never the raw token.
- Tokens are single-use (``used_at``) and expire (``expires_at``).
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
    # SHA-256 hex digest of the raw token; the raw token is only ever emailed.
    token_hash = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    ip_address = Column(String, nullable=True)

    user = relationship("User")
