"""
A system administrator sets a temporary password for another user (POST /api/users/{id}/reset-password).

For a user who forgot their password and has no email for the self-service reset. The user must
choose a new one at the next sign-in, their open sessions end, and the action is in the audit
trail. Changing a password through update_user still needs the current password (5f147c8).
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.database import SessionLocal
from app.core.dependencies import get_current_user
from app.core.security import create_access_token, get_password_hash, password_fingerprint, verify_password
from app.models import User, UserRole
from app.models.security_audit_log import AuditLog
from app.modules.users.router import reset_user_password
from app.schemas.user import AdminPasswordReset
from fastapi.security import HTTPAuthorizationCredentials

OLD, TEMP = "Old-Pass-123!", "Temp-Pass-456!"


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(User).filter(User.username.like("pwreset_%")).delete(synchronize_session=False)
    s.commit()
    s.close()


def _user(db, name, role=UserRole.USER):
    u = User(username=f"pwreset_{name}", email=f"pwreset_{name}@example.com", hashed_password=get_password_hash(OLD),
             role=role, is_active=True, must_change_password=False)
    db.add(u)
    db.commit()
    return u


def _creds(user):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=create_access_token(
        {"sub": user.username, "pwv": password_fingerprint(user.hashed_password)}))


def _req(path="/api/users/1/reset-password", ip="192.0.2.44"):
    return SimpleNamespace(url=SimpleNamespace(path=path), client=SimpleNamespace(host=ip))


def test_admin_sets_a_temporary_password_the_user_must_change(db):
    admin, user = _user(db, "admin", UserRole.ADMIN), _user(db, "user")
    old_session = _creds(user)
    out = reset_user_password(user.id, AdminPasswordReset(new_password=TEMP), _req(), db, admin)
    assert out.id == user.id
    db.refresh(user)
    assert verify_password(TEMP, user.hashed_password) and user.must_change_password is True

    # the session the user had before is over
    with pytest.raises(HTTPException) as exc:
        get_current_user(old_session, db, _req("/api/assets/"))
    assert exc.value.status_code == 401

    # signed in with the temporary password, only the password change is open
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(user), db, _req("/api/assets/"))
    assert exc.value.status_code == 403 and "Password change required" in exc.value.detail

    record = (db.query(AuditLog).filter(AuditLog.action == "user.password_reset", AuditLog.target_id == user.id)
              .order_by(AuditLog.id.desc()).first())
    assert record.username == admin.username and record.ip_address == "192.0.2.44"
    assert record.detail == f"Set a temporary password for '{user.username}'; it must be changed at the next sign-in"
    assert TEMP not in record.detail


def test_only_system_administrators_and_never_on_their_own_account(db):
    admin, manager, user = _user(db, "admin", UserRole.ADMIN), _user(db, "mgr", UserRole.MANAGER), _user(db, "user")
    with pytest.raises(HTTPException) as exc:
        reset_user_password(user.id, AdminPasswordReset(new_password=TEMP), _req(), db, manager)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        reset_user_password(admin.id, AdminPasswordReset(new_password=TEMP), _req(), db, admin)
    assert exc.value.status_code == 400
    db.refresh(user)
    db.refresh(admin)
    assert verify_password(OLD, user.hashed_password) and verify_password(OLD, admin.hashed_password)


def test_unknown_user_is_not_found(db):
    admin = _user(db, "admin", UserRole.ADMIN)
    with pytest.raises(HTTPException) as exc:
        reset_user_password(987654321, AdminPasswordReset(new_password=TEMP), _req(), db, admin)
    assert exc.value.status_code == 404


@pytest.mark.parametrize("weak", ["short1!", "alllowercase1!", "NoDigits!!", "NoSpecial123"])
def test_the_temporary_password_meets_the_password_policy(weak):
    with pytest.raises(ValidationError):
        AdminPasswordReset(new_password=weak)
