"""Tests for the Asset change-history diff (app/modules/assets/change_history.py)
and its wiring into AssetService.update_asset.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back (same pattern as test_asset_hosting.py).
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
from app.models.asset_locations import AssetLocation
from app.models.asset_owners import AssetOwner
from app.models.user import User
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
    row = User(username=f"achist_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset_type(db, type_name: str) -> AssetType:
    row = AssetType(type_name=f"{type_name}_{_next()}", category="compute")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, user, **overrides) -> Asset:
    asset_type = _make_asset_type(db, "Generic")
    defaults = dict(asset_name=f"achist-asset-{_next()}", asset_type_id=asset_type.id, user_id=user.id)
    defaults.update(overrides)
    row = Asset(**defaults)
    db.add(row)
    db.flush()
    return row


def _make_location(db, user, site_name: str) -> AssetLocation:
    row = AssetLocation(site_name=site_name, user_id=user.id)
    db.add(row)
    db.flush()
    return row


def _make_owner(db, user, full_name: str) -> AssetOwner:
    row = AssetOwner(full_name=full_name, user_id=user.id)
    db.add(row)
    db.flush()
    return row


def test_scalar_field_change_produces_one_entry(db, user):
    asset = _make_asset(db, user, hostname="old-host")
    _updated, changes = AssetService.update_asset(db, asset.id, {"hostname": "new-host"})

    hostname_changes = [c for c in changes if c["field"] == "hostname"]
    assert len(hostname_changes) == 1
    entry = hostname_changes[0]
    assert entry["label"] == "Hostname"
    assert entry["category"] == "overview"
    assert entry["old"] == "old-host"
    assert entry["new"] == "new-host"


def test_unchanged_value_produces_no_entry(db, user):
    asset = _make_asset(db, user, hostname="same-host")
    _updated, changes = AssetService.update_asset(db, asset.id, {"hostname": "same-host"})
    assert [c for c in changes if c["field"] == "hostname"] == []


def test_last_audit_date_is_never_diffed(db, user):
    """update_asset auto-stamps last_audit_date on every call - diffing it
    would add a noisy entry to every single update, real or not."""
    asset = _make_asset(db, user, hostname="same-host")
    _updated, changes = AssetService.update_asset(db, asset.id, {"hostname": "same-host"})
    assert [c for c in changes if c["field"] == "last_audit_date"] == []


def test_foreign_key_field_resolves_to_display_name(db, user):
    old_location = _make_location(db, user, "Main DC")
    new_location = _make_location(db, user, "Branch Office")
    asset = _make_asset(db, user, location_id=old_location.id)

    _updated, changes = AssetService.update_asset(db, asset.id, {"location_id": new_location.id})

    location_changes = [c for c in changes if c["field"] == "location_id"]
    assert len(location_changes) == 1
    assert location_changes[0]["label"] == "Location"
    assert location_changes[0]["old"] == "Main DC"
    assert location_changes[0]["new"] == "Branch Office"


def test_multiple_fields_changed_at_once_each_get_their_own_entry(db, user):
    owner = _make_owner(db, user, "Ali Mansori")
    asset = _make_asset(db, user, hostname="h1", os_name="Ubuntu")

    _updated, changes = AssetService.update_asset(db, asset.id, {
        "hostname": "h2", "os_name": "Windows Server", "owner_id": owner.id,
    })

    changed_fields = {c["field"] for c in changes}
    assert changed_fields == {"hostname", "os_name", "owner_id"}


def test_setting_a_field_for_the_first_time_shows_none_as_old_value(db, user):
    asset = _make_asset(db, user)
    assert asset.model is None

    _updated, changes = AssetService.update_asset(db, asset.id, {"model": "LaserJet Pro M501"})

    model_changes = [c for c in changes if c["field"] == "model"]
    assert len(model_changes) == 1
    assert model_changes[0]["old"] is None
    assert model_changes[0]["new"] == "LaserJet Pro M501"
