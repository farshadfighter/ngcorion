"""
API keys (app/core/api_keys.py, app/modules/api_keys): a key's token signs in as its own service account
whose permissions are the key's scopes; every way a token must be refused (wrong secret, unknown id,
revoked, expired, an address the key does not allow); what a key can never get (administrator routes,
user management, credential profiles, write to hardening or system settings, delete); renewing and
changing a key; the service accounts kept out of password sign-in and of the user lists; the expiry
alert; the audit trail.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core import api_keys as K
from app.core.database import engine
from app.core.dependencies import get_current_user, require_admin, require_permission
from app.models import User, UserPermission, UserRole
from app.models.api_key import ApiKey
from app.models.security_audit_log import AuditLog as SecurityAuditLog
from app.modules.api_keys import router as R


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _admin(db, role=UserRole.ADMIN):
    _seq[0] += 1
    u = User(username=f"keyadmin_{_seq[0]}", hashed_password="x", role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def _req(ip="10.0.0.9", method="GET", path="/api/assets/"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), method=method, url=SimpleNamespace(path=path))


def _body(name="SIEM export", scopes=(("asset_list", False), ("logs", False)), ips=(), days=90):
    return R.KeyIn(name=name, scopes=[R.ScopeIn(module=m, write=w) for m, w in scopes], allowed_ips=list(ips),
                   expires_at=datetime.utcnow() + timedelta(days=days))


def _sign_in(db, token, ip="10.0.0.9", method="GET"):
    return get_current_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), db, _req(ip, method))


def _new(db, admin, **kw):
    out = R.create_key(_body(**kw), request=_req(), current_user=admin, db=db)
    return out["key"], out["token"]


def test_token_format():
    key_id, secret = K.new_secret()
    token = K.token_of(key_id, secret)
    assert token.startswith("ngk_") and K.parse(token) == (key_id, secret)
    assert K.parse("ngk_short_x") is None and K.parse("eyJhbGciOi.jwt.token") is None
    assert K.clean_networks(["10.1.2.3", "10.1.0.0/16", " ", "10.1.2.3"]) == ["10.1.2.3", "10.1.0.0/16"]
    with pytest.raises(ValueError):
        K.clean_networks(["not an address"])
    assert K.ip_allowed("10.1.9.9", ["10.1.0.0/16"]) and not K.ip_allowed("10.2.0.1", ["10.1.0.0/16"])
    assert K.ip_allowed("anything", None)


def test_a_key_signs_in_as_its_account_with_its_scopes(db):
    admin = _admin(db)
    key, token = _new(db, admin)
    assert key["account"].startswith("api-siem-export") and key["status"] == "active"
    assert key["prefix"] == token[: len(key["prefix"])]
    row = db.get(ApiKey, key["id"])
    assert row.secret_hash == K.hash_secret(K.parse(token)[1]) and token.split("_", 2)[2] not in row.secret_hash
    user = _sign_in(db, token)
    assert user.username == key["account"] and user.role == UserRole.USER and user.auth_source == "apikey"
    assert db.get(ApiKey, key["id"]).last_used_ip == "10.0.0.9"
    # its permissions are the scopes, nothing more
    require_permission("asset_list", "read")(current_user=user, db=db)
    require_permission("logs", "read")(current_user=user, db=db)
    for module, kind in (("asset_list", "write"), ("asset_list", "delete"), ("user_management", "read"),
                         ("hardening", "read")):
        with pytest.raises(HTTPException) as e:
            require_permission(module, kind)(current_user=user, db=db)
        assert e.value.status_code == 403, (module, kind)
    with pytest.raises(HTTPException) as e:
        require_admin(user)
    assert e.value.status_code == 403


def test_refused_tokens(db):
    admin = _admin(db)
    key, token = _new(db, admin, ips=["192.168.10.0/24"])
    assert _sign_in(db, token, ip="192.168.10.40")
    with pytest.raises(HTTPException) as e:
        _sign_in(db, token, ip="10.0.0.9")
    assert e.value.status_code == 403
    key_id, secret = K.parse(token)
    for bad in (K.token_of(key_id, secret[:-2] + "xx"), K.token_of("a" * 10, secret), "ngk_garbage"):
        with pytest.raises(HTTPException) as e:
            _sign_in(db, bad, ip="192.168.10.40")
        assert e.value.status_code == 401 and e.value.detail == "Invalid API key"
    row = db.get(ApiKey, key["id"])
    row.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.flush()
    with pytest.raises(HTTPException) as e:
        _sign_in(db, token, ip="192.168.10.40")
    assert e.value.status_code == 401 and e.value.detail == "API key has expired"
    row.expires_at = datetime.utcnow() + timedelta(days=5)
    R.revoke_key(key["id"], request=_req(), current_user=admin, db=db)
    with pytest.raises(HTTPException) as e:
        _sign_in(db, token, ip="192.168.10.40")
    assert e.value.status_code == 401
    assert db.get(User, row.user_id).is_active is False


def test_what_a_key_can_never_get(db):
    admin = _admin(db)
    for scopes in ((("user_management", False),), (("credential_profiles", False),), (("hardening", True),),
                   (("system_config", True),), (("logs", True),), (("backup", True),)):
        with pytest.raises(HTTPException) as e:
            R.create_key(_body(scopes=scopes), request=_req(), current_user=admin, db=db)
        assert e.value.status_code == 400, scopes
    for days in (-1, 400):
        with pytest.raises(HTTPException):
            R.create_key(_body(days=days), request=_req(), current_user=admin, db=db)
    key, token = _new(db, admin, scopes=(("asset_list", True),))
    perms = db.query(UserPermission).filter(UserPermission.user_id == db.get(ApiKey, key["id"]).user_id).all()
    assert [(p.can_read, p.can_write, p.can_delete) for p in perms] == [(True, True, False)]
    # managing keys is for system administrators, so never for a key
    for route in R.router.routes:
        assert any(d.call is require_admin for d in route.dependant.dependencies), route.path


def test_renew_and_change(db):
    admin = _admin(db)
    key, old = _new(db, admin)
    new = R.renew_key(key["id"], request=_req(), current_user=admin, db=db)["token"]
    with pytest.raises(HTTPException):
        _sign_in(db, old)
    user = _sign_in(db, new)
    R.update_key(key["id"], _body(name="SIEM", scopes=(("cve", False), ("remediation", True))), request=_req(),
                 current_user=admin, db=db)
    require_permission("remediation", "write")(current_user=user, db=db)
    with pytest.raises(HTTPException):
        require_permission("asset_list", "read")(current_user=user, db=db)
    listed = R.list_keys(current_user=admin, db=db)
    mine = [k for k in listed["keys"] if k["id"] == key["id"]][0]
    assert mine["name"] == "SIEM" and mine["renewed_at"] and "token" not in mine
    assert "hardening" not in listed["modules"]["write"]


def test_service_accounts_stay_out_of_people_lists_and_password_sign_in(db):
    from app.modules.auth.service import AuthService
    from app.modules.users.service import UserService
    admin = _admin(db)
    key, _ = _new(db, admin)
    account = db.get(User, db.get(ApiKey, key["id"]).user_id)
    assert account.username not in [u.username for u in UserService(db).get_all_users()]
    assert account.username not in [u.username for u in UserService(db).search_users("api-")]
    with pytest.raises(HTTPException) as e:
        UserService(db).get_user_by_id(account.id)
    assert e.value.status_code == 404
    assert AuthService(db).authenticate_user(account.username, "anything") is False


def test_expiry_alert_and_audit_trail(db):
    from app.modules.alerts.events import EVENTS
    admin = _admin(db)
    key, _ = _new(db, admin, days=5)
    now = datetime.utcnow()
    found = EVENTS["system.api_key_expiring"].evaluate(db, {"days": 14}, now, now)
    assert any(p.key == f"api_key:{key['id']}" for p in found)
    assert not any(p.key == f"api_key:{key['id']}" for p in EVENTS["system.api_key_expiring"].evaluate(db, {"days": 3}, now, now))
    R.renew_key(key["id"], request=_req(), current_user=admin, db=db)
    R.revoke_key(key["id"], request=_req(), current_user=admin, db=db)
    actions = [r.action for r in db.query(SecurityAuditLog).filter(SecurityAuditLog.target_id == key["id"],
                                                                     SecurityAuditLog.action.like("api_key.%"))]
    assert {"api_key.create", "api_key.renew", "api_key.revoke"} <= set(actions)
    after = EVENTS["system.api_key_expiring"].evaluate(db, {"days": 14}, now, now)
    assert all(p.key != f"api_key:{key['id']}" for p in after)          # revoked: no more warning
