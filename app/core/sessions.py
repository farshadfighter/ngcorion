"""
The idle timeout of web sessions (app/models/user_session.py).

open_session() records a new access token at login; touch() runs on every
authenticated request (from get_current_user) and either notes the use - at
most once a minute, so a busy page does not write on every call - or, after
SESSION_IDLE_TIMEOUT_MINUTES without a request, ends the session for good by
revoking its token, exactly as logout does. A token issued before this existed
(no row yet) gets one on its first use.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.revoked_token import RevokedToken
from app.models.user_session import UserSession

_SEEN_RESOLUTION = timedelta(seconds=60)


def _aware(value: datetime) -> datetime:
    """A stored time as UTC-aware (SQLite, used by some tests, keeps no time zone)."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _expiry(payload: dict) -> datetime:
    return datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)


def open_session(db: Session, payload: dict, user_id: int, ip_address: Optional[str]) -> None:
    """Record a newly issued token; also prunes sessions whose tokens have expired."""
    now = datetime.now(timezone.utc)
    db.query(UserSession).filter(UserSession.expires_at < now).delete(synchronize_session=False)
    db.add(UserSession(jti=str(payload["jti"]), user_id=user_id, created_at=now, last_seen_at=now,
                       expires_at=_expiry(payload), ip_address=(ip_address or "")[:64] or None))
    db.commit()


def touch(db: Session, payload: dict, user_id: int) -> None:
    """Note a use of this session, or end it (HTTP 401) if it has been idle too long."""
    jti = payload.get("jti")
    if not jti:
        return  # tokens from before revocation existed simply expire
    now = datetime.now(timezone.utc)
    session = db.get(UserSession, str(jti))
    if session is None:
        db.add(UserSession(jti=str(jti), user_id=user_id, created_at=now, last_seen_at=now,
                           expires_at=_expiry(payload)))
        db.commit()
        return
    idle = timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES)
    last_seen = _aware(session.last_seen_at)
    if now - last_seen > idle:
        if db.get(RevokedToken, str(jti)) is None:
            db.add(RevokedToken(jti=str(jti), user_id=user_id, expires_at=session.expires_at))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session ended after a period of inactivity. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if now - last_seen >= _SEEN_RESOLUTION:
        session.last_seen_at = now
        db.commit()
