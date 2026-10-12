"""
Two-step sign-in (TOTP) of one user account (app/core/mfa.py, app/modules/auth/mfa_router.py).

A row exists once the user has started setting it up or the policy has given them a deadline. It
is never deleted while the user exists: `version` only ever grows and every access token carries
the value it was issued under, so turning two-step sign-in on, off or resetting it ends every
session issued before. (Deleting the row would bring the version back to 0 and revive tokens
issued before it was first turned on.)
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, Text

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class UserMfa(Base):
    __tablename__ = "user_mfa"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    enabled = Column(Boolean, nullable=False, default=False)
    # Base32 TOTP secret, encrypted (credential_crypto PURPOSE_MFA). While setting up, the new
    # secret waits in pending_secret until a code from it is confirmed.
    secret = Column(Text, nullable=True)
    pending_secret = Column(Text, nullable=True)
    last_used_step = Column(Integer, nullable=True)        # a code is never accepted twice
    recovery_codes = Column(JSON, nullable=False, default=list)  # salted hashes of the unused codes
    version = Column(Integer, nullable=False, default=0)
    enabled_at = Column(DateTime(timezone=True), nullable=True)
    # When the policy requires two-step sign-in for this user's role: the end of their grace period.
    deadline = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)
