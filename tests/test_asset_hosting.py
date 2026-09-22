"""Tests for the Asset hosting feature: the VM/Application/Database
keyword classification, and create/update validation that a hosting server
must be specified for those types.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_topology.py / test_asset_deletion.py).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.user import User
from app.modules.assets.hosting import requires_hosting
from app.modules.assets.service import AssetService


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


_seq = [0]


def _next() -> int:
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def user(db) -> User:
    row = User(username=f"hosting_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset_type(db, type_name: str) -> AssetType:
    row = AssetType(type_name=f"{type_name}_{_next()}", category="compute")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, user, type_name="Physical Server") -> Asset:
    asset_type = _make_asset_type(db, type_name)
    row = Asset(asset_name=f"hosting-asset-{_next()}", asset_type_id=asset_type.id, user_id=user.id)
    db.add(row)
    db.flush()
    return row


# ======================================================================
# requires_hosting (pure function)
# ======================================================================

@pytest.mark.parametrize("type_name", [
    "Virtual Machine", "VM", "vm", "Application", "App Server", "Database", "DB",
    "MySQL Database", "Web Application",
])
def test_requires_hosting_true_for_hosted_types(type_name):
    assert requires_hosting(type_name) is True


@pytest.mark.parametrize("type_name", [
    "Physical Server", "Cisco Router", "Switch", "Firewall", "Load Balancer", None, "",
])
def test_requires_hosting_false_for_infrastructure_types(type_name):
    assert requires_hosting(type_name) is False


def test_requires_hosting_does_not_false_positive_on_substrings():
    # "app" must not match words that merely contain it as a substring.
    assert requires_hosting("Happy Path Monitor") is False


# ======================================================================
# create_asset validation
# ======================================================================

def test_create_hosted_type_without_host_fails(db, user):
    asset_type = _make_asset_type(db, "Virtual Machine")
    with pytest.raises(ValueError, match="hosted"):
        AssetService.create_asset(db, {
            "asset_name": "vm-no-host", "asset_type_id": asset_type.id, "user_id": user.id,
        })


def test_create_hosted_type_with_host_succeeds(db, user):
    server = _make_asset(db, user)
    asset_type = _make_asset_type(db, "Application")
    app_asset = AssetService.create_asset(db, {
        "asset_name": "app-with-host", "asset_type_id": asset_type.id,
        "hosted_on_asset_id": server.id, "hosted_vlan": "110", "user_id": user.id,
    })
    assert app_asset.hosted_on_asset_id == server.id
    assert app_asset.hosted_vlan == "110"


def test_create_non_hosted_type_without_host_succeeds(db, user):
    asset_type = _make_asset_type(db, "Cisco Router")
    router = AssetService.create_asset(db, {
        "asset_name": "router-no-host", "asset_type_id": asset_type.id, "user_id": user.id,
    })
    assert router.hosted_on_asset_id is None


def test_create_with_nonexistent_host_fails(db, user):
    asset_type = _make_asset_type(db, "Database")
    with pytest.raises(ValueError, match="does not exist"):
        AssetService.create_asset(db, {
            "asset_name": "db-bad-host", "asset_type_id": asset_type.id,
            "hosted_on_asset_id": 2_000_000_000, "user_id": user.id,
        })


# ======================================================================
# update_asset validation
# ======================================================================

def test_update_to_hosted_type_without_existing_host_fails(db, user):
    asset = _make_asset(db, user, type_name="Generic Asset")
    hosted_type = _make_asset_type(db, "VM")
    with pytest.raises(ValueError, match="hosted"):
        AssetService.update_asset(db, asset.id, {"asset_type_id": hosted_type.id})


def test_update_setting_host_on_existing_asset_succeeds(db, user):
    server = _make_asset(db, user)
    asset_type = _make_asset_type(db, "Database")
    db_asset = AssetService.create_asset(db, {
        "asset_name": "existing-db", "asset_type_id": asset_type.id,
        "hosted_on_asset_id": server.id, "user_id": user.id,
    })
    other_server = _make_asset(db, user)
    updated = AssetService.update_asset(db, db_asset.id, {"hosted_on_asset_id": other_server.id})
    assert updated.hosted_on_asset_id == other_server.id


def test_update_self_host_fails(db, user):
    server = _make_asset(db, user)
    asset_type = _make_asset_type(db, "Application")
    app_asset = AssetService.create_asset(db, {
        "asset_name": "self-host-app", "asset_type_id": asset_type.id,
        "hosted_on_asset_id": server.id, "user_id": user.id,
    })
    with pytest.raises(ValueError, match="cannot be hosted on itself"):
        AssetService.update_asset(db, app_asset.id, {"hosted_on_asset_id": app_asset.id})


def test_update_keeps_existing_host_when_type_changes_between_hosted_types(db, user):
    """An already-hosted asset switching between two hosted-requiring types
    (still has a host, just a different flavor of hosted type) must not
    re-trigger the "must specify a host" error - it already has one."""
    server = _make_asset(db, user)
    vm_type = _make_asset_type(db, "VM")
    app_type = _make_asset_type(db, "Application")
    asset = AssetService.create_asset(db, {
        "asset_name": "vm-becomes-app", "asset_type_id": vm_type.id,
        "hosted_on_asset_id": server.id, "user_id": user.id,
    })
    updated = AssetService.update_asset(db, asset.id, {"asset_type_id": app_type.id})
    assert updated.asset_type_id == app_type.id
    assert updated.hosted_on_asset_id == server.id
