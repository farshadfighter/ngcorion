"""
Web sessions: one row per access token (its "jti" claim), for the idle timeout.

Access tokens are JWTs that live ACCESS_TOKEN_EXPIRE_MINUTES. On its own that
is an absolute limit only: a token left in an unattended browser keeps working
until it expires. Each authenticated request therefore records when the
session was last used (at most once a minute), and get_current_user ends a
session - revokes its token - once it has gone SESSION_IDLE_TIMEOUT_MINUTES
without a request (app/core/sessions.py). The web UI also signs out after the
same time without keyboard or mouse input, because its automatic refreshes
would otherwise count as use.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class UserSession(Base):
    """A signed-in session: its token id, its user, and when it was last used."""
    __tablename__ = "user_sessions"

    jti = Column(String(64), primary_key=True)          # the token's "jti" claim
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)  # the token's "exp"
    ip_address = Column(String(64), nullable=True)
