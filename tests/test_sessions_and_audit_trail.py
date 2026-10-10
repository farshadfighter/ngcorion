"""
Idle session timeout (app/core/sessions.py), the append-only audit trail
(audit_logs trigger, migration a1d3f5b7c9e2), the login notice endpoint, and the
log-clearing endpoint keeping the sign-in history.

Needs PostgreSQL (DATABASE_URL) migrated to head.
"""
import importlib
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.core import sessions
from app.models import LoginLog, RevokedToken, User, UserRole, UserSession
from app.models.security_audit_log import AuditLog, log_action

_seq = [0]


def _name(prefix):
    _seq[0] += 1
    return f"{prefix}_{_seq[0]}_{datetime.now().timestamp():.0f}"


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def user(db):
    u = User(username=_name("sess_user"), hashed_password="x", role=UserRole.ADMIN)
    db.add(u)
    db.commit()
    yield u
    db.rollback()
    db.execute(text("SET LOCAL ngcorion.audit_maintenance = 'on'"))
    db.execute(text("DELETE FROM audit_logs WHERE user_id = :u"), {"u": u.id})
    db.execute(text("DELETE FROM users WHERE id = :u"), {"u": u.id})
    db.commit()


def _payload(user):
    token = create_access_token({"sub": user.username, "role": "admin"})
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


# ── idle timeout ───────────────────────────────────────────────────────────

def test_a_session_is_recorded_and_its_use_noted(db, user):
    payload = _payload(user)
    sessions.open_session(db, payload, user.id, "10.0.0.5")
    row = db.get(UserSession, payload["jti"])
    assert (row.user_id, row.ip_address) == (user.id, "10.0.0.5")
    # Used again within a minute: no write needed.
    seen = row.last_seen_at
    sessions.touch(db, payload, user.id)
    db.refresh(row)
    assert row.last_seen_at == seen
    # Used after more than a minute: noted.
    row.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.commit()
    sessions.touch(db, payload, user.id)
    db.refresh(row)
    assert datetime.now(timezone.utc) - row.last_seen_at < timedelta(seconds=10)


def test_an_idle_session_ends_and_its_token_is_revoked(db, user):
    payload = _payload(user)
    sessions.open_session(db, payload, user.id, None)
    row = db.get(UserSession, payload["jti"])
    row.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES + 1)
    db.commit()
    with pytest.raises(HTTPException) as exc:
        sessions.touch(db, payload, user.id)
    assert exc.value.status_code == 401
    assert "inactivity" in exc.value.detail
    assert db.get(RevokedToken, payload["jti"]) is not None


def test_a_token_from_before_the_upgrade_gets_a_session(db, user):
    payload = _payload(user)
    assert db.get(UserSession, payload["jti"]) is None
    sessions.touch(db, payload, user.id)
    assert db.get(UserSession, payload["jti"]) is not None


def test_get_current_user_enforces_the_idle_timeout(db, user):
    from fastapi.security import HTTPAuthorizationCredentials
    from app.core.dependencies import get_current_user
    from app.core.security import password_fingerprint
    token = create_access_token({"sub": user.username, "role": "admin",
                                 "pwv": password_fingerprint(user.hashed_password)})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    assert get_current_user(creds, db).id == user.id
    jti = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])["jti"]
    row = db.get(UserSession, jti)
    row.last_seen_at = datetime.now(timezone.utc) - timedelta(hours=5)
    db.commit()
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds, db)
    assert exc.value.status_code == 401
    # ...and stays refused: the token is revoked now.
    with pytest.raises(HTTPException):
        get_current_user(creds, db)


# ── the audit trail is append-only ─────────────────────────────────────────

def _entry(db, user):
    log_action(db, user_id=user.id, username=user.username, action="test.append_only", module="test",
               detail="probe")
    return db.query(AuditLog).filter(AuditLog.user_id == user.id, AuditLog.action == "test.append_only").one()


def test_audit_entries_cannot_be_changed_or_deleted(db, user):
    entry = _entry(db, user)
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("UPDATE audit_logs SET detail = 'tampered' WHERE id = :i"), {"i": entry.id})
    db.rollback()
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("DELETE FROM audit_logs WHERE id = :i"), {"i": entry.id})
    db.rollback()
    assert db.get(AuditLog, entry.id).detail == "probe"


def test_deleting_a_user_keeps_their_audit_entries(db):
    u = User(username=_name("gone_user"), hashed_password="x", role=UserRole.USER)
    db.add(u)
    db.commit()
    entry_id = _entry(db, u).id
    db.delete(u)
    db.commit()           # ON DELETE SET NULL is allowed through
    entry = db.get(AuditLog, entry_id)
    assert entry is not None and entry.user_id is None and entry.detail == "probe"


def test_the_restore_engine_may_replace_the_trail(db, user):
    entry_id = _entry(db, user).id
    db.execute(text("SET LOCAL ngcorion.audit_maintenance = 'on'"))
    db.execute(text("DELETE FROM audit_logs WHERE id = :i"), {"i": entry_id})
    db.commit()
    db.expire_all()
    assert db.get(AuditLog, entry_id) is None


def test_the_restore_engine_connects_in_maintenance_mode():
    from app.modules.sysbackup import dbdump
    with dbdump.connect() as conn:
        assert conn.execute("SHOW ngcorion.audit_maintenance").fetchone()[0] == "on"


# ── login notice; sign-in history is not clearable ─────────────────────────

def test_login_banner_endpoint(monkeypatch):
    router = importlib.import_module("app.modules.auth.router")
    monkeypatch.setattr(settings, "LOGIN_BANNER", None)
    assert router.login_banner() == {"banner": None,
                                      "idle_timeout_minutes": settings.SESSION_IDLE_TIMEOUT_MINUTES}
    monkeypatch.setattr(settings, "LOGIN_BANNER", "Authorised staff only.")
    assert router.login_banner()["banner"] == "Authorised staff only."


def test_clearing_the_logs_keeps_the_sign_in_history(db, user):
    clear = importlib.import_module("app.modules.logs.clear_router")
    marker = _name("login_probe")
    db.add(LoginLog(username=marker, success=False, ip_address="10.9.9.9", message="probe"))
    db.commit()
    result = clear.clear_all_logs(current_user=user, db=db)
    assert "login" not in result["deleted"]
    assert db.query(LoginLog).filter(LoginLog.username == marker).count() == 1
    db.query(LoginLog).filter(LoginLog.username == marker).delete()
    db.commit()
