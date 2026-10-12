"""
Sign-in against a real Active Directory (Samba AD DC or Windows), when one is configured:

  NGC_TEST_AD_SERVER    dc1.corp.local          NGC_TEST_AD_BASE   DC=corp,DC=local
  NGC_TEST_AD_CA        path of the CA (PEM)    NGC_TEST_AD_BIND   CN=svc-ngc-ldap,CN=Users,DC=corp,DC=local
  NGC_TEST_AD_BIND_PW   service account password

The directory holds: a.rezaei (in Team-Security, which is in NGC-SecOps), m.karimi (in NGC-Admins),
n.nogroup (in no NGC group), d.disabled (disabled, in NGC-SecOps); passwords in NGC_TEST_AD_USERS
as name=password,name=password. Skipped otherwise (CI has no directory).
"""
import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.database import SessionLocal
from app.models import LoginLog, User, UserRole
from app.models.system_config import SystemConfigSetting
from app.modules.auth.router import login
from app.modules.directory import service as ds
from app.modules.directory.ldap import Session as LdapSession
from app.schemas.auth import UserLogin

ENV = {k: os.environ.get(k) for k in ("NGC_TEST_AD_SERVER", "NGC_TEST_AD_BASE", "NGC_TEST_AD_CA",
                                      "NGC_TEST_AD_BIND", "NGC_TEST_AD_BIND_PW", "NGC_TEST_AD_USERS")}
pytestmark = pytest.mark.skipif(not all(ENV.values()), reason="no test directory configured")
USERS = dict(p.split("=", 1) for p in (ENV["NGC_TEST_AD_USERS"] or "").split(",") if "=" in p)


def _cfg(security="ldaps", servers=None):
    base = ENV["NGC_TEST_AD_BASE"]
    return {**ds.DEFAULT_CONFIG, "enabled": True, "kind": "ad", "servers": servers or [ENV["NGC_TEST_AD_SERVER"]],
            "security": security, "base_dn": base, "bind_dn": ENV["NGC_TEST_AD_BIND"],
            "bind_password": ENV["NGC_TEST_AD_BIND_PW"], "ca_pem": open(ENV["NGC_TEST_AD_CA"]).read(),
            "mappings": [{"group_dn": f"CN=NGC-Admins,CN=Users,{base}", "role": "admin", "permissions": []},
                         {"group_dn": f"CN=NGC-SecOps,CN=Users,{base}", "role": "manager",
                          "permissions": [{"module": "asset_list", "can_read": True, "can_write": True}]}]}


@pytest.fixture
def db():
    s = SessionLocal()
    s.query(SystemConfigSetting).filter(SystemConfigSetting.section.in_((ds.SECTION, ds.STATUS_SECTION))).delete()
    s.commit()
    yield s
    s.rollback()
    s.query(LoginLog).filter(LoginLog.username.in_(list(USERS))).delete(synchronize_session=False)
    s.query(User).filter(User.username.in_(list(USERS)), User.auth_source == "ldap").delete(synchronize_session=False)
    s.query(SystemConfigSetting).filter(SystemConfigSetting.section.in_((ds.SECTION, ds.STATUS_SECTION))).delete()
    s.commit()
    s.close()


def _login(db, name):
    req = SimpleNamespace(client=SimpleNamespace(host="10.99.0.1"), headers={"user-agent": "pytest"})
    return login(UserLogin(username=name, password=USERS[name]), req, db)


@pytest.mark.parametrize("security", ["ldaps", "starttls"])
def test_service_account_nested_groups_and_passwords(security):
    with LdapSession(ds.settings_from(_cfg(security, ["unreachable.invalid", ENV["NGC_TEST_AD_SERVER"]]))) as d:
        user = d.find_user("A.Rezaei")
        groups = d.groups_of(user)
        assert any(g.lower().startswith("cn=ngc-secops,") for g in groups)          # through Team-Security
        assert d.check_password(user, USERS["a.rezaei"]) and not d.check_password(user, "wrong")
        assert d.find_user("d.disabled").disabled
        assert d.find_user("*") is None


def test_sign_in_end_to_end(db):
    ds.save_config(db, _cfg(), SimpleNamespace(id=None))
    out = _login(db, "a.rezaei")
    assert out["role"] == "manager" and out["auth_source"] == "ldap"
    assert db.query(User).filter(User.username == "m.karimi").first() is None
    assert _login(db, "m.karimi")["role"] == "admin"
    for name in ("n.nogroup", "d.disabled"):
        with pytest.raises(HTTPException) as exc:
            _login(db, name)
        assert exc.value.status_code == 401
    status = ds.check_accounts(db)
    assert status["ok"] and status["checked"] == 2 and status["turned_off"] == 0
    assert db.query(User).filter(User.username == "m.karimi").one().role == UserRole.ADMIN
