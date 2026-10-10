"""
Licensing v3 in the main app: the license covers a number of assets.

What is protected here (app/core/asset_entitlement.py):

* assets cannot be added past the license's limit - not through the asset
  service, not through bulk adds (which add what fits), and not through any
  other code path (the before_flush guard);
* while the inventory holds more assets than the license covers, audits and
  hardening run only on the first max_assets assets (the oldest by id), from
  the API and from the scheduler, and are refused before any connection to the
  target is made;
* without a valid license nothing is licensed;
* the audit/hardening quotas are gone.

Needs a migrated PostgreSQL database; each test runs inside a transaction that
is rolled back. The database may already hold assets, so limits are set
relative to the current count.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-tests-only-not-real")

import asyncio
import json

import pytest
from fastapi import FastAPI
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core import asset_entitlement as ent
from app.core import dependencies as app_dependencies
from app.core import license_state
from app.core.database import engine, get_db
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.user import User, UserRole


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture(autouse=True)
def clean_license_state():
    license_state._license_state.__init__()
    license_state._signed_token = None
    license_state._max_seen = None
    yield
    license_state._license_state.__init__()
    license_state._signed_token = None
    license_state._max_seen = None


def license_for(max_assets, valid=True):
    """A verified license state with this asset limit (None = unlimited)."""
    license_state.set_license_state({
        "valid": valid, "message": "ok", "plan_code": "NGC-BUS-250-1Y", "plan_name": "NGCorion Business",
        "is_pilot_mode": False, "limits": {"max_assets": max_assets, "addon_packs": 0},
    })


def asgi_post(app, path: str, body: dict):
    """One JSON POST straight through the ASGI interface (starlette's TestClient needs httpx,
    which this project does not depend on; same approach as test_cors_policy.py)."""
    payload = json.dumps(body).encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "scheme": "http", "server": ("testserver", 80), "client": ("127.0.0.1", 1234),
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
    }
    sent = {"done": False}
    captured = {"body": b""}

    async def receive():
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
            captured["headers"] = {k.decode().lower(): v.decode() for k, v in message["headers"]}
        elif message["type"] == "http.response.body":
            captured["body"] += message.get("body", b"")

    asyncio.run(app(scope, receive, send))
    return captured["status"], captured["headers"], captured["body"].decode()


_seq = [0]


def _next():
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def user(db):
    row = User(username=f"licensing_test_user_{_next()}", hashed_password="x", role=UserRole.ADMIN)
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def asset_type(db):
    row = AssetType(type_name=f"Licensing Server {_next()}", category="compute")
    db.add(row)
    db.flush()
    return row


def add_asset(db, user, asset_type):
    row = Asset(asset_name=f"licensing-asset-{_next()}", asset_type_id=asset_type.id, user_id=user.id)
    db.add(row)
    db.flush()
    return row


# ==================== the quotas are gone ====================

def test_the_audit_and_hardening_quotas_are_gone():
    for name in ("require_quota", "check_quota_available", "consume_quota_on_success", "require_asset_quota"):
        assert not hasattr(app_dependencies, name)
    assert not hasattr(license_state, "update_usage")


# ==================== adding assets ====================

def test_assets_can_be_added_up_to_the_limit_and_not_past_it(db, user, asset_type):
    from app.modules.assets.service import AssetService

    license_for(ent.count_assets(db) + 2)
    for _ in range(2):
        AssetService.create_asset(db, {"asset_name": f"svc-{_next()}", "asset_type_id": asset_type.id,
                                       "user_id": user.id})
    with pytest.raises(ent.AssetLimitExceeded) as exc:
        AssetService.create_asset(db, {"asset_name": f"svc-{_next()}", "asset_type_id": asset_type.id,
                                       "user_id": user.id})
    assert exc.value.status_code == 403
    assert exc.value.headers == {"X-Asset-Limit": "true"}
    assert "no more can be added" in exc.value.detail


def test_no_code_path_can_insert_past_the_limit(db, user, asset_type):
    """The before_flush guard: a plain db.add() past the limit fails at flush."""
    license_for(ent.count_assets(db) + 1)
    add_asset(db, user, asset_type)
    with pytest.raises(ent.AssetLimitExceeded):
        add_asset(db, user, asset_type)


def test_bulk_adds_get_the_remaining_room(db, user, asset_type):
    used = ent.count_assets(db)
    license_for(used + 3)
    assert ent.remaining_capacity(db) == 3
    license_for(used - 1 if used else 0)
    assert ent.remaining_capacity(db) == 0
    license_for(None)
    assert ent.remaining_capacity(db) is None


def test_excel_import_adds_what_fits_and_reports_the_rest(db, user, asset_type):
    from io import BytesIO

    from openpyxl import Workbook

    from app.utils.excel_utils import import_assets_from_excel

    license_for(ent.count_assets(db) + 1)
    wb = Workbook()
    ws = wb.active
    ws.title = "Overview"
    ws.append(["Asset Name", "Hostname", "Type"])
    names = [f"xl-{_next()}" for _ in range(3)]
    for name in names:
        ws.append([name, name, asset_type.type_name])
    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    result = import_assets_from_excel(buf, db, user)

    assert result["created"] == 1
    assert sum("limit of" in e for e in result["errors"]) == 2


def test_without_a_valid_license_maintenance_writes_are_not_blocked(db, user, asset_type):
    """The guard only enforces a valid license's finite limit: with no license the API is closed
    by the middleware, and tools such as a database restore must still write."""
    license_for(0, valid=False)
    add_asset(db, user, asset_type)        # must not raise
    with pytest.raises(ent.AssetLimitExceeded):
        ent.check_asset_capacity(db)       # but the explicit checks refuse


# ==================== audits and hardening: the first N assets ====================

def test_over_the_limit_only_the_oldest_assets_are_licensed(db, user, asset_type):
    license_for(None)
    first = add_asset(db, user, asset_type)
    second = add_asset(db, user, asset_type)
    position_of_first = ent._position(db, first.id)

    license_for(position_of_first)          # the limit drops (offline pilot, smaller plan)

    assert ent.is_asset_licensed(db, first.id)
    assert not ent.is_asset_licensed(db, second.id)
    ent.require_licensed_asset(db, first.id)
    with pytest.raises(ent.AssetLimitExceeded) as exc:
        ent.require_licensed_asset(db, second.id)
    assert "beyond the license's limit" in exc.value.detail

    usage = ent.usage(db)
    assert usage["over_limit"] is True
    assert usage["licensed_through_id"] == first.id


def test_unlimited_covers_everything_and_no_license_covers_nothing(db, user, asset_type):
    asset = add_asset(db, user, asset_type)
    license_for(None)
    ent.require_licensed_asset(db, asset.id)
    ent.require_licensed_asset(db, None)    # a target outside the inventory: unlimited only
    assert ent.usage(db)["unlimited"] is True

    license_for(10_000_000)
    with pytest.raises(ent.AssetLimitExceeded):
        ent.require_licensed_asset(db, None)

    license_for(None, valid=False)
    with pytest.raises(ent.AssetLimitExceeded):
        ent.require_licensed_asset(db, asset.id)


def test_hardening_by_finding_or_action_resolves_the_asset(db, user, asset_type):
    """The Cisco/FortiGate hardening endpoints name a finding or an action, not an asset."""
    from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
    from app.models.hardening import HardeningAction

    asset = add_asset(db, user, asset_type)
    session = AuditSession(asset_id=asset.id, user_id=user.id, target_ip="192.0.2.1",
                           device_type=list(DeviceType)[0])
    db.add(session)
    db.flush()
    result = AuditResult(session_id=session.id, status=CheckStatus.FAIL)
    db.add(result)
    db.flush()
    action = HardeningAction(audit_result_id=result.id, user_id=user.id, asset_id=asset.id,
                             audit_session_id=session.id, check_number="X-1", check_title="x",
                             action_type="preview", status="pending", commands_json="[]")
    db.add(action)
    db.flush()

    assert ent.asset_of_result(db, result.id) == asset.id
    assert ent.asset_of_action(db, action.id) == asset.id
    assert ent.asset_of_result(db, None) is None
    assert ent.asset_of_action(db, 987654321) is None


def test_a_scheduled_audit_of_an_unlicensed_asset_is_refused(db, user, asset_type):
    from app.modules.scheduling.audit_dispatch import run_audit

    license_for(None)
    first = add_asset(db, user, asset_type)
    second = add_asset(db, user, asset_type)
    license_for(ent._position(db, first.id))

    with pytest.raises(PermissionError, match="beyond the license's limit"):
        run_audit("linux", db, second.id, user.id, {})


def test_the_audit_route_refuses_before_connecting(db, user, asset_type, monkeypatch):
    """End to end through FastAPI: an audit of an asset outside the license is a 403 with
    X-Asset-Limit, and the audit service (the SSH connection) is never called."""
    import importlib

    from app.modules.linux.audit.service import LinuxAuditService

    # The package re-exports `router` (the APIRouter), which shadows the module of that name.
    linux_router = importlib.import_module("app.modules.linux.audit.router")

    called = []
    monkeypatch.setattr(LinuxAuditService, "execute_linux_audit", staticmethod(lambda **kw: called.append(kw)))

    license_for(None)
    first = add_asset(db, user, asset_type)
    second = add_asset(db, user, asset_type)
    license_for(ent._position(db, first.id))

    app = FastAPI()
    app.include_router(linux_router.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[app_dependencies.get_current_user] = lambda: user
    status, headers, text = asgi_post(app, "/api/audit/linux/execute", {
        "asset_id": second.id, "ssh_username": "u", "ssh_password": "p", "profile": "L1"})

    assert status == 403, text
    assert headers.get("x-asset-limit") == "true"
    assert "beyond the license's limit" in text
    assert called == []

    # The covered asset goes through to the audit service.
    asgi_post(app, "/api/audit/linux/execute", {
        "asset_id": first.id, "ssh_username": "u", "ssh_password": "p", "profile": "L1"})
    assert [c["asset_id"] for c in called] == [first.id]
