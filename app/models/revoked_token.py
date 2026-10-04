"""
Revoked access tokens (server-side logout).

Access tokens are JWTs: valid until they expire, without a server lookup.
Logging out records the token's id (its "jti" claim) here, and
get_current_user refuses any token whose id is listed, so a token copied
before logout stops working at once instead of at its expiry. A row is
only needed until the token would have expired anyway; expired rows are
pruned on every logout.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class RevokedToken(Base):
    """An access token ended by logout; kept until the token would have expired anyway."""
    __tablename__ = "revoked_tokens"

    jti = Column(String(64), primary_key=True)          # the token's "jti" claim
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)  # the token's "exp"
    revoked_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
