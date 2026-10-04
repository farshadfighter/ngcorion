"""
Self-service password change (PUT /auth/me/password) and the forced change
of a password someone else chose (User.must_change_password): accounts made
by an administrator, and the first admin from scripts/init_db.py.
"""
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException
from fastapi.dependencies.utils import get_dependant
from fastapi.security import HTTPAuthorizationCredentials

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.dependencies import PASSWORD_CHANGE_ALLOWED, get_current_user
from app.core.security import create_access_token, get_password_hash, password_fingerprint
from app.models import User, UserRole
from app.modules.auth.router import OwnPasswordChange, change_own_password, read_current_user

OLD, NEW = "Old-Pass-123", "New-Pass-456!"


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(User).filter(User.username.like("pwchange_%")).delete(synchronize_session=False)
    s.commit()
    s.close()


def _user(db, must_change=True):
    u = User(username="pwchange_probe", email="pwchange_probe@example.com", hashed_password=get_password_hash(OLD),
             role=UserRole.USER, is_active=True, must_change_password=must_change)
    db.add(u)
    db.commit()
    return u


def _creds(user):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=create_access_token(
        {"sub": user.username, "pwv": password_fingerprint(user.hashed_password)}))


def _req(path):
    return SimpleNamespace(url=SimpleNamespace(path=path), client=SimpleNamespace(host="127.0.0.1"))


def test_fastapi_injects_the_request_into_the_dependency():
    assert get_dependant(path="/x", call=get_current_user).request_param_name == "request"


def test_forced_change_blocks_everything_but_the_allowed_endpoints(db):
    user = _user(db)
    creds = _creds(user)
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds, db, _req("/api/assets/"))
    assert exc.value.status_code == 403 and "Password change required" in exc.value.detail
    for path in PASSWORD_CHANGE_ALLOWED:
        assert get_current_user(creds, db, _req(path)).id == user.id
    assert read_current_user(user, db)["must_change_password"] is True


def test_own_password_change_clears_the_flag_and_rotates_the_session(db):
    user = _user(db)
    old_creds = _creds(user)
    with pytest.raises(HTTPException) as exc:
        change_own_password(OwnPasswordChange(current_password="wrong", new_password=NEW), _req("/auth/me/password"),
                            user, db)
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException):   # the same password again
        change_own_password(OwnPasswordChange(current_password=OLD, new_password=OLD), _req("/auth/me/password"),
                            user, db)
    out = change_own_password(OwnPasswordChange(current_password=OLD, new_password=NEW), _req("/auth/me/password"),
                              user, db)
    assert out["must_change_password"] is False
    db.refresh(user)
    assert user.must_change_password is False
    # the old token no longer matches the password; the new one works everywhere
    with pytest.raises(HTTPException):
        get_current_user(old_creds, db, _req("/auth/me"))
    new = HTTPAuthorizationCredentials(scheme="Bearer", credentials=out["access_token"])
    assert jwt.decode(out["access_token"], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])["sub"] == user.username
    assert get_current_user(new, db, _req("/api/assets/")).id == user.id


def test_weak_new_password_is_refused():
    with pytest.raises(ValueError):
        OwnPasswordChange(current_password=OLD, new_password="short")


def test_accounts_made_by_an_administrator_must_change_their_password(db):
    from app.modules.users.service import UserService
    from app.schemas.user import UserCreate
    admin = User(username="pwchange_admin", email="pwchange_admin@example.com", hashed_password="x",
                 role=UserRole.ADMIN, is_active=True)
    db.add(admin)
    db.commit()
    created = UserService(db).create_user(
        UserCreate(username="pwchange_new", email="pwchange_new@example.com", password="Strong-Pass-1!", role="user"),
        actor=admin)
    assert created.must_change_password is True


def test_existing_accounts_are_not_forced(db):
    user = _user(db, must_change=False)
    assert get_current_user(_creds(user), db, _req("/api/assets/")).id == user.id
