"""
Sign-in with Active Directory / LDAP (app/modules/directory): group mapping, which password is
checked, account creation at the first sign-in, the account rules for directory users, and the
periodic check. A fake directory stands in for the server here; tests/test_directory_live.py runs
the same paths against a real one when one is configured.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.database import SessionLocal
from app.core.dependencies import get_current_user
from app.core.security import get_password_hash
from app.models import LoginLog, User, UserPermission, UserRole
from app.models.security_audit_log import AuditLog
from app.models.system_config import SystemConfigSetting
from app.modules.auth.router import OwnPasswordChange, change_own_password, login
from app.modules.directory import ldap as dl
from app.modules.directory import router as dr
from app.modules.directory import service as ds
from app.modules.directory.ldap import DirectoryUnavailable, DirectoryUser
from app.modules.users.service import UserService
from app.schemas.auth import UserLogin
from app.schemas.user import UserUpdate

ADMINS = "CN=NGC-Admins,CN=Users,DC=corp,DC=local"
SECOPS = "CN=NGC-SecOps,CN=Users,DC=corp,DC=local"
NOC = "CN=NGC-NOC,CN=Users,DC=corp,DC=local"

MAPPINGS = [
    {"group_dn": ADMINS, "role": "admin", "permissions": []},
    {"group_dn": SECOPS, "role": "manager", "permissions": [
        {"module": "asset_list", "can_read": True, "can_write": True, "can_delete": False}]},
    {"group_dn": NOC, "role": "user", "permissions": [
        {"module": "asset_list", "can_read": True, "can_write": False, "can_delete": True},
        {"module": "dashboard", "can_read": True}]},
]


class FakeDirectory:
    """Stands in for ldap.Session: users {name: (password, disabled, [group DNs])}."""
    users = {}
    down = False

    def __init__(self, settings):
        if FakeDirectory.down:
            raise DirectoryUnavailable("dc1.corp.local: no answer in time")
        self.address = settings.servers[0]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def close(self):
        pass

    def find_user(self, name):
        for key, (_, disabled, _) in FakeDirectory.users.items():
            if key.lower() == name.lower():
                return DirectoryUser(dn=f"CN={key},CN=Users,DC=corp,DC=local", username=key,
                                     email=f"{key}@corp.local", display_name=key, disabled=disabled)
        return None

    def groups_of(self, user):
        return {dl.norm_dn(g) for g in FakeDirectory.users[user.username][2]}

    def check_password(self, user, password):
        return bool(password) and FakeDirectory.users[user.username][0] == password


@pytest.fixture
def db(monkeypatch):
    s = SessionLocal()
    for section in (ds.SECTION, ds.STATUS_SECTION):
        s.query(SystemConfigSetting).filter(SystemConfigSetting.section == section).delete()
    s.commit()
    monkeypatch.setattr(ds, "LdapSession", FakeDirectory)
    FakeDirectory.users = {"A.Rezaei": ("Ali-Pass-2026!", False, [SECOPS, NOC]),
                           "m.karimi": ("Mehdi-Pass-2026!", False, [ADMINS]),
                           "n.nogroup": ("NoGroup-Pass-2026!", False, ["CN=Other,DC=corp,DC=local"]),
                           "d.disabled": ("Disabled-Pass-2026!", True, [SECOPS])}
    FakeDirectory.down = False
    yield s
    s.rollback()
    names = ["a.rezaei", "m.karimi", "n.nogroup", "d.disabled", "dir_local_admin", "dir_local_user"]
    ids = [u.id for u in s.query(User).filter(User.username.in_(names))]
    s.query(LoginLog).filter(LoginLog.username.in_(names + ["A.Rezaei", "ghost"])).delete(synchronize_session=False)
    if ids:
        s.query(User).filter(User.id.in_(ids)).delete(synchronize_session=False)
    for section in (ds.SECTION, ds.STATUS_SECTION):
        s.query(SystemConfigSetting).filter(SystemConfigSetting.section == section).delete()
    s.commit()
    s.close()


def _configure(db, enabled=True, mappings=MAPPINGS):
    admin = db.query(User).filter(User.role == UserRole.ADMIN).first() or SimpleNamespace(id=None)
    ds.save_config(db, {**ds.DEFAULT_CONFIG, "enabled": enabled, "servers": ["dc1.corp.local"],
                        "base_dn": "DC=corp,DC=local", "bind_dn": "CN=svc,DC=corp,DC=local",
                        "bind_password": "Svc-Pass-2026!", "mappings": mappings}, admin)


def _req(ip="10.20.30.40", path="/auth/login"):
    return SimpleNamespace(url=SimpleNamespace(path=path), client=SimpleNamespace(host=ip),
                           headers={"user-agent": "pytest"}, method="POST")


def _login(db, name, password, ip="10.20.30.40"):
    return login(UserLogin(username=name, password=password), _req(ip), db)


def _local(db, name, role=UserRole.ADMIN, password="Local-Pass-2026!"):
    u = User(username=name, email=f"{name}@example.com", hashed_password=get_password_hash(password),
             role=role, is_active=True)
    db.add(u)
    db.commit()
    return u


# ── Mapping ───────────────────────────────────────────────────────────────

def test_mapping_takes_the_highest_role_and_every_permission():
    cfg = {"mappings": MAPPINGS}
    g = ds.resolve(cfg, [SECOPS.lower(), NOC])
    assert g.role == "manager"
    assert g.permissions["asset_list"] == {"read": True, "write": True, "delete": True}
    assert g.permissions["dashboard"]["read"]
    assert ds.resolve(cfg, [ADMINS, NOC]).role == "admin"
    assert ds.resolve(cfg, [ADMINS]).permissions == {}
    assert ds.resolve(cfg, ["CN=Other,DC=corp,DC=local"]) is None
    # DN spelling (case, spaces after commas) does not matter
    assert ds.resolve(cfg, ["cn=ngc-noc, cn=users, dc=corp, dc=local"]).role == "user"


def test_password_is_stored_encrypted_and_never_returned(db):
    _configure(db)
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == ds.SECTION).one()
    assert row.config_json["bind_password"].startswith(ds.ENC_PREFIX)
    assert "Svc-Pass-2026!" not in str(row.config_json)
    pub = ds.public_config(db)
    assert "bind_password" not in pub and pub["has_password"] is True
    assert ds.load_config(db)["bind_password"] == "Svc-Pass-2026!"
    # saving without a password keeps the stored one
    admin = SimpleNamespace(id=None)
    ds.save_config(db, {**pub, "bind_password": ""}, admin)
    assert ds.load_config(db)["bind_password"] == "Svc-Pass-2026!"


# ── Sign-in ───────────────────────────────────────────────────────────────

def test_first_sign_in_creates_the_account_from_its_groups(db):
    _configure(db)
    out = _login(db, "a.rezaei", "Ali-Pass-2026!")
    user = db.query(User).filter(User.username == "a.rezaei").one()
    assert out["role"] == "manager" and user.auth_source == "ldap" and user.email == "A.Rezaei@corp.local"
    assert user.external_dn.startswith("CN=A.Rezaei")
    perms = {p.module.value: (p.can_read, p.can_write, p.can_delete)
             for p in db.query(UserPermission).filter(UserPermission.user_id == user.id)}
    assert perms["asset_list"] == (True, True, True) and perms["dashboard"][0]
    assert out["auth_source"] == "ldap"
    # the directory decides the case of the name; signing in again reuses the account
    _login(db, "A.REZAEI", "Ali-Pass-2026!")
    assert db.query(User).filter(User.username == "a.rezaei").count() == 1


@pytest.mark.parametrize("name,password", [("a.rezaei", "wrong"), ("a.rezaei", ""), ("ghost", "x"),
                                           ("n.nogroup", "NoGroup-Pass-2026!"),
                                           ("d.disabled", "Disabled-Pass-2026!")])
def test_refused_sign_ins_all_look_the_same(db, name, password):
    _configure(db)
    with pytest.raises(HTTPException) as exc:
        _login(db, name, password)
    assert exc.value.status_code == 401 and exc.value.detail == "Incorrect username or password"
    assert db.query(User).filter(User.username == name).first() is None


def test_unreachable_directory_is_a_503_and_local_accounts_still_work(db):
    _configure(db)
    local = _local(db, "dir_local_user", UserRole.USER)
    FakeDirectory.down = True
    with pytest.raises(HTTPException) as exc:
        _login(db, "a.rezaei", "Ali-Pass-2026!")
    assert exc.value.status_code == 503
    assert _login(db, local.username, "Local-Pass-2026!")["access_token"]


def test_local_admin_sign_in_is_recorded_as_emergency(db):
    _configure(db)
    _local(db, "dir_local_admin", UserRole.ADMIN)
    _login(db, "dir_local_admin", "Local-Pass-2026!")
    row = db.query(AuditLog).filter(AuditLog.action == "auth.emergency_login",
                                    AuditLog.username == "dir_local_admin").first()
    assert row is not None
    from datetime import datetime, timedelta
    from app.modules.alerts.events import EVENTS
    problems = EVENTS["system.emergency_login"].evaluate(db, {}, datetime.utcnow(), datetime.utcnow() - timedelta(minutes=5))
    assert any(p.source_label == "dir_local_admin" for p in problems)


def test_directory_off_means_local_only(db):
    _configure(db, enabled=False)
    with pytest.raises(HTTPException):
        _login(db, "a.rezaei", "Ali-Pass-2026!")


# ── Account rules for directory users ─────────────────────────────────────

def test_directory_accounts_keep_their_password_in_the_directory(db):
    _configure(db)
    _login(db, "m.karimi", "Mehdi-Pass-2026!")
    user = db.query(User).filter(User.username == "m.karimi").one()
    with pytest.raises(HTTPException) as exc:
        change_own_password(OwnPasswordChange(current_password="Mehdi-Pass-2026!", new_password="New-Pass-2026!x"),
                            _req(path="/auth/me/password"), user, db)
    assert "directory" in exc.value.detail
    admin = _local(db, "dir_local_admin", UserRole.ADMIN)
    svc = UserService(db)
    with pytest.raises(HTTPException):
        svc.reset_password(user.id, "Temp-Pass-2026!x", actor=admin)
    with pytest.raises(HTTPException):
        svc.update_user(user.id, UserUpdate(role="guest"), current_user_id=admin.id)
    # the phone number, language and on/off are still the administrator's
    svc.update_user(user.id, UserUpdate(phone="+989121234567"), current_user_id=admin.id)


# ── The periodic check ────────────────────────────────────────────────────

def test_check_follows_the_directory(db):
    _configure(db)
    _login(db, "a.rezaei", "Ali-Pass-2026!")
    _login(db, "m.karimi", "Mehdi-Pass-2026!")
    rezaei = db.query(User).filter(User.username == "a.rezaei").one()
    token = _login(db, "a.rezaei", "Ali-Pass-2026!")["access_token"]
    # a.rezaei moves to the NOC team only; m.karimi is disabled in AD
    FakeDirectory.users["A.Rezaei"] = ("Ali-Pass-2026!", False, [NOC])
    FakeDirectory.users["m.karimi"] = ("Mehdi-Pass-2026!", True, [ADMINS])
    status = ds.check_accounts(db)
    assert status["ok"] and status["turned_off"] >= 1 and status["updated"] >= 1
    db.refresh(rezaei)
    assert rezaei.role == UserRole.USER
    karimi = db.query(User).filter(User.username == "m.karimi").one()
    assert not karimi.is_active and karimi.disabled_by_directory
    # out of every mapped group: off, and the open session stops working
    FakeDirectory.users["A.Rezaei"] = ("Ali-Pass-2026!", False, [])
    ds.check_accounts(db)
    with pytest.raises(HTTPException) as exc:
        get_current_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), db,
                         _req(path="/api/assets/"))
    assert exc.value.status_code == 403
    # back in a group: the next sign-in turns it on again
    FakeDirectory.users["A.Rezaei"] = ("Ali-Pass-2026!", False, [SECOPS])
    _login(db, "a.rezaei", "Ali-Pass-2026!")
    db.refresh(rezaei)
    assert rezaei.is_active and not rezaei.disabled_by_directory


def test_check_changes_nothing_when_the_directory_is_down(db):
    _configure(db)
    _login(db, "a.rezaei", "Ali-Pass-2026!")
    FakeDirectory.down = True
    status = ds.check_accounts(db)
    assert status["ok"] is False and "no answer" in status["error"]
    assert db.query(User).filter(User.username == "a.rezaei").one().is_active
    from datetime import datetime, timedelta
    from app.modules.alerts.events import EVENTS
    assert EVENTS["system.directory_unreachable"].evaluate(db, {}, datetime.utcnow(),
                                                          datetime.utcnow() - timedelta(minutes=5))


# ── Settings validation and the filter escaping ───────────────────────────

def test_settings_validation():
    with pytest.raises(ValueError):
        dr.DirectoryConfig(servers=["dc1.corp.local; rm -rf /"])
    with pytest.raises(ValueError):
        dr.DirectoryConfig(user_filter="objectClass=user")
    with pytest.raises(ValueError):
        dr.DirectoryConfig(ca_pem="not a certificate")
    with pytest.raises(ValueError):
        dr.GroupMapping(group_dn=SECOPS, role="manager", permissions=[{"module": "no_such_module"}])
    ok = dr.DirectoryConfig(servers=[" dc1.corp.local:636 ", ""], user_filter="(objectClass=user)")
    assert ok.servers == ["dc1.corp.local:636"]


def test_values_in_filters_are_escaped(monkeypatch):
    seen = []

    class Conn:
        response = []
        result = {"result": 0}

        def search(self, base, flt, **kw):
            seen.append(flt)
            return True

    s = object.__new__(dl.Session)
    s.s = dl.Settings(kind="ad", servers=["x"], security="ldaps", base_dn="DC=x", bind_dn="b", bind_password="p")
    s.conn, s.address = Conn(), "x"
    assert s.find_user("*)(objectClass=*") is None
    assert "\\2a\\29\\28objectClass=\\2a" in seen[0]
    s.groups_of(DirectoryUser(dn="CN=a*b,DC=x", username="a", email=None, display_name=None, disabled=False))
    assert "CN=a\\2ab,DC=x" in seen[1]


def test_empty_password_never_reaches_a_bind():
    with pytest.raises(dl.LDAPBindError):
        dl._open(dl.Settings(kind="ad", servers=["x"], security="ldaps", base_dn="", bind_dn="",
                             bind_password=""), "x", "CN=a", "")


def test_turning_directory_sign_in_off_ends_directory_sessions(db):
    _configure(db)
    token = _login(db, "a.rezaei", "Ali-Pass-2026!")["access_token"]
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    assert get_current_user(creds, db, _req(path="/auth/me")).username == "a.rezaei"
    assert ds.end_directory_sessions(db) >= 1
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds, db, _req(path="/auth/me"))
    assert exc.value.status_code == 401


def test_plain_ldap_is_a_choice_and_never_touches_tls(monkeypatch):
    assert dr.DirectoryConfig(security="plain").security == "plain"
    with pytest.raises(ValueError):
        dr.DirectoryConfig(security="ssl3")
    s = dl.Settings(kind="ldap", servers=["ldap.corp.local"], security="plain", base_dn="dc=x", bind_dn="b",
                    bind_password="p")
    server = dl._server(s, "ldap.corp.local")
    assert server.port == 389 and not server.ssl and server.tls is None
    assert dl._server(dl.Settings(**{**s.__dict__, "security": "ldaps"}), "h").port == 636
    calls = []

    class Conn:
        result = {"result": 8, "description": "strongerAuthRequired"}

        def __init__(self, *a, **kw):
            pass

        def open(self):
            calls.append("open")

        def start_tls(self):
            calls.append("start_tls")
            return True

        def bind(self):
            return False

        def unbind(self):
            pass

    monkeypatch.setattr(dl, "Connection", Conn)
    with pytest.raises(dl.EncryptionRequired):
        dl._open(s, "ldap.corp.local", "uid=a", "pw")
    assert calls == ["open"]                              # no StartTLS in plain mode
    with pytest.raises(DirectoryUnavailable) as exc:
        dl.Session(s)
    assert "requires an encrypted connection" in str(exc.value)
