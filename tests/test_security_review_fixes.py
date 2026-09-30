"""Regression tests for the WSTG security review fixes."""
import importlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.dependencies import get_current_user
from app.core.security import create_access_token, get_password_hash, password_fingerprint
from app.models import User, UserRole
from app.models.security_audit_log import AuditLog
from app.models.user_permission import ModuleEnum, UserPermission
from app.modules.users.service import UserService
from app.schemas.user import PermissionCreate, UserCreate, UserUpdate
from app.utils.excel_utils import neutralize_formula

PASSWORD = "Str0ng-Passw0rd!"


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    tables = [User.__table__, UserPermission.__table__, AuditLog.__table__]
    Base.metadata.create_all(bind=engine, tables=tables)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))


def _user(db, uid, role, perms=()):
    user = User(
        id=uid, username=f"u{uid}", email=f"u{uid}@example.com",
        hashed_password=get_password_hash(PASSWORD), role=role, is_active=True,
    )
    db.add(user)
    db.flush()
    for module, r, w, d in perms:
        db.add(UserPermission(user_id=uid, module=ModuleEnum(module), can_read=r, can_write=w, can_delete=d))
    db.commit()
    return user


@pytest.fixture
def delegate(db):
    """A plain user who was given full user_management rights, nothing else."""
    return _user(db, 10, UserRole.USER, [("user_management", True, True, True)])


# --- WSTG-ATHZ-03: vertical privilege escalation via user management -------

def test_delegate_cannot_create_admin(db, delegate):
    with pytest.raises(HTTPException) as exc:
        UserService(db).create_user(
            UserCreate(username="evil", email="evil@example.com", password=PASSWORD, role="admin"),
            actor=delegate,
        )
    assert exc.value.status_code == 403
    assert db.query(User).filter(User.username == "evil").first() is None


def test_delegate_cannot_create_role_above_their_own(db, delegate):
    with pytest.raises(HTTPException) as exc:
        UserService(db).create_user(
            UserCreate(username="mgr", email="mgr@example.com", password=PASSWORD, role="manager"),
            actor=delegate,
        )
    assert exc.value.status_code == 403


def test_delegate_cannot_grant_permissions_they_do_not_hold(db, delegate):
    with pytest.raises(HTTPException) as exc:
        UserService(db).create_user(
            UserCreate(
                username="proxy", email="proxy@example.com", password=PASSWORD, role="user",
                permissions=[PermissionCreate(module="hardening", can_read=True, can_write=True, can_delete=False)],
            ),
            actor=delegate,
        )
    assert exc.value.status_code == 403


def test_delegate_can_still_create_peer_with_held_permissions(db, delegate):
    created = UserService(db).create_user(
        UserCreate(
            username="peer", email="peer@example.com", password=PASSWORD, role="user",
            permissions=[PermissionCreate(module="user_management", can_read=True, can_write=False, can_delete=False)],
        ),
        actor=delegate,
    )
    assert created.role == UserRole.USER


def test_delegate_cannot_change_admin_email_or_delete_admin(db, delegate):
    _user(db, 1, UserRole.ADMIN)
    _user(db, 2, UserRole.ADMIN)
    service = UserService(db)
    with pytest.raises(HTTPException) as exc:
        service.update_user(1, UserUpdate(email="attacker@example.com"), current_user_id=delegate.id)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        service.delete_user(2, current_user_id=delegate.id)
    assert exc.value.status_code == 403
    assert db.get(User, 1).email == "u1@example.com"


def test_admin_cannot_deactivate_last_active_admin_or_self(db):
    admin = _user(db, 1, UserRole.ADMIN)
    with pytest.raises(HTTPException):
        UserService(db).update_user(admin.id, UserUpdate(is_active=False), current_user_id=admin.id)
    assert db.get(User, 1).is_active


# --- WSTG-SESS: tokens must die with the password they were issued for ------

def test_token_rejected_after_password_change(db):
    user = _user(db, 1, UserRole.USER)
    token = create_access_token({"sub": user.username, "pwv": password_fingerprint(user.hashed_password)})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    assert get_current_user(creds, db).id == user.id

    user.hashed_password = get_password_hash("An0ther-Passw0rd!")
    db.commit()
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds, db)
    assert exc.value.status_code == 401


def test_token_without_fingerprint_is_rejected(db):
    user = _user(db, 1, UserRole.USER)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=create_access_token({"sub": user.username}))
    with pytest.raises(HTTPException):
        get_current_user(creds, db)


# --- CSV / formula injection ------------------------------------------------

@pytest.mark.parametrize("payload", ["=HYPERLINK(\"http://x\")", "+cmd", "-2+3", "@SUM(A1)", "\t=1"])
def test_formula_payloads_are_neutralized(payload):
    assert neutralize_formula(payload) == "'" + payload


@pytest.mark.parametrize("value", ["DC01", 42, -3.5, None, "10.0.0.1"])
def test_ordinary_values_pass_through(value):
    assert neutralize_formula(value) == value


# --- Device CLI injection via generated configuration -----------------------

def _rel(interface, vlan, label):
    other = SimpleNamespace(label=label)
    return SimpleNamespace(
        source_component_id=1, source_interface=interface, destination_interface=None,
        destination_component=other, source_component=None, vlan=vlan,
    )


def test_cisco_generator_blocks_newline_injection():
    from app.modules.configuration.templates import generate_cisco_commands
    lines = generate_cisco_commands(SimpleNamespace(id=1), [_rel("Gi0/1", "10\nno aaa new-model", "SW\nusername x privilege 15")])
    assert all("\n" not in line for line in lines)
    assert not any("username" in line and line.startswith("username") for line in lines)
    assert not any("switchport access vlan" in line for line in lines)


def test_generators_skip_malformed_interface_names():
    from app.modules.configuration.templates import generate_cisco_commands, generate_fortinet_commands
    rel = _rel('port1"\nconfig system admin', "20", "fw")
    assert not any(line.startswith("interface") for line in generate_cisco_commands(SimpleNamespace(id=1), [rel]))
    assert not any(line.startswith("edit") for line in generate_fortinet_commands(SimpleNamespace(id=1), [rel]))


def test_fortinet_alias_cannot_break_out_of_quotes():
    from app.modules.configuration.templates import generate_fortinet_commands
    lines = generate_fortinet_commands(SimpleNamespace(id=1), [_rel("port1", "20", 'x" \nset allowaccess telnet')])
    alias = next(line for line in lines if line.startswith("set alias"))
    assert alias.count('"') == 2
    assert "set vlanid 20" in lines


# --- Stored XSS via CVE reference links --------------------------------------

def test_nvd_reference_url_only_accepts_http_schemes():
    from app.modules.cve.nvd_sync import _reference_url
    assert _reference_url({"references": [{"url": "javascript:alert(1)"}]}) is None
    assert _reference_url({"references": [
        {"url": "javascript:alert(1)"}, {"url": "https://nvd.nist.gov/vuln/detail/CVE-1"},
    ]}) == "https://nvd.nist.gov/vuln/detail/CVE-1"


# --- License swap (business logic) -------------------------------------------

def test_license_activation_requires_admin_once_a_license_is_valid(db, monkeypatch):
    license_router = importlib.import_module("app.modules.license.router")
    monkeypatch.setattr(license_router, "get_license_state", lambda: SimpleNamespace(valid=True))
    monkeypatch.setattr(license_router, "_activate", lambda data, request: "activated")
    data = license_router.LicenseActivateRequest(license_key="KEY")

    with pytest.raises(HTTPException) as exc:
        license_router.activate_license(data, request=None, credentials=None, db=db)
    assert exc.value.status_code == 401

    user = _user(db, 5, UserRole.USER)
    token = create_access_token({"sub": user.username, "pwv": password_fingerprint(user.hashed_password)})
    with pytest.raises(HTTPException) as exc:
        license_router.activate_license(
            data, request=None, credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), db=db,
        )
    assert exc.value.status_code == 403


def test_license_activation_open_while_unlicensed(db, monkeypatch):
    license_router = importlib.import_module("app.modules.license.router")
    monkeypatch.setattr(license_router, "get_license_state", lambda: SimpleNamespace(valid=False))
    monkeypatch.setattr(license_router, "_activate", lambda data, request: "activated")
    data = license_router.LicenseActivateRequest(license_key="KEY")
    assert license_router.activate_license(data, request=None, credentials=None, db=db) == "activated"
