"""Tests for the asset-based design suggestion (app/modules/design/suggestion.py
and GET /api/design/suggest): a read-only preview of a standard SAFE campus
design sized to the real asset inventory, with real assets slotted into
matching roles.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_design_templates.py).
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
from app.modules.design.suggestion import (
    classify_component_type,
    determine_scale,
    suggest_design,
)


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
    row = User(username=f"sugg_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, type_name: str, port_count=None) -> Asset:
    asset_type = AssetType(type_name=f"{type_name}_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(
        asset_name=f"sugg-asset-{_next()}",
        asset_type_id=asset_type.id,
        ip_address="10.0.1.1",
        port_count=port_count,
    )
    db.add(row)
    db.flush()
    return row


# ======================================================================
# classify_component_type
# ======================================================================

@pytest.mark.parametrize(
    "type_name,expected",
    [
        ("Fortinet FortiGate 100F", "firewall"),
        ("Cisco ASA 5506", "firewall"),
        ("Cisco ISR 4331 Router", "router"),
        ("Cisco Catalyst 9300 Switch", "switch"),
        ("F5 Load Balancer", "load_balancer"),
        ("Cisco Wireless LAN Controller", "wireless"),
        ("Public Cloud Endpoint", "cloud"),
        ("Ubuntu Linux Server", "server"),
        ("Windows Server 2022", "server"),
        ("Label Printer", None),
        (None, None),
        ("", None),
    ],
)
def test_classify_component_type(type_name, expected):
    assert classify_component_type(type_name) == expected


# ======================================================================
# determine_scale
# ======================================================================

@pytest.mark.parametrize(
    "total,expected",
    [(0, "small"), (49, "small"), (50, "medium"), (200, "medium"), (201, "large"), (5000, "large")],
)
def test_determine_scale(total, expected):
    assert determine_scale(total) == expected


# ======================================================================
# suggest_design
# ======================================================================

def test_suggest_design_with_no_assets_returns_small_and_no_matches(db, user):
    suggestion = suggest_design(db)
    assert suggestion.scale == "small"
    assert suggestion.total_assets == 0
    assert suggestion.matched_assets == 0
    assert len(suggestion.components) > 0
    assert all(c.suggested_asset_id is None for c in suggestion.components)


def test_suggest_design_matches_a_real_firewall_to_the_perimeter_firewall_slot(db, user):
    fw = _make_asset(db, "Fortinet FortiGate", port_count=8)
    suggestion = suggest_design(db)

    perimeter = next(c for c in suggestion.components if c.label == "Perimeter Firewall")
    assert perimeter.suggested_asset_id == fw.id
    assert perimeter.suggested_asset_port_count == 8
    assert suggestion.matched_assets == 1


def test_suggest_design_prefers_the_higher_port_count_switch_for_the_first_slot(db, user):
    small_switch = _make_asset(db, "Cisco Switch", port_count=8)
    big_switch = _make_asset(db, "Cisco Switch", port_count=48)
    suggestion = suggest_design(db)

    switch_components = [c for c in suggestion.components if c.component_type == "switch"]
    matched_ids = [c.suggested_asset_id for c in switch_components if c.suggested_asset_id]
    # The 48-port switch must be matched before the 8-port one.
    assert matched_ids[0] == big_switch.id
    assert matched_ids[1] == small_switch.id


def test_suggest_design_does_not_reuse_the_same_asset_for_two_slots(db, user):
    _make_asset(db, "Cisco Switch")
    suggestion = suggest_design(db)

    matched_ids = [c.suggested_asset_id for c in suggestion.components if c.suggested_asset_id]
    assert len(matched_ids) == len(set(matched_ids))
    assert suggestion.matched_assets == 1


def test_suggest_design_ignores_unclassifiable_assets(db, user):
    _make_asset(db, "Label Printer")
    suggestion = suggest_design(db)
    assert suggestion.matched_assets == 0


def test_suggest_design_scale_reflects_total_asset_count(db, user):
    for _ in range(60):
        _make_asset(db, "Ubuntu Server")
    suggestion = suggest_design(db)
    assert suggestion.total_assets == 60
    assert suggestion.scale == "medium"


def test_suggest_design_relationships_reference_component_keys(db, user):
    suggestion = suggest_design(db)
    keys = {c.key for c in suggestion.components}
    for rel in suggestion.relationships:
        assert rel.source_key in keys
        assert rel.destination_key in keys


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_get_design_suggestion(db, user):
    from app.modules.design.router import get_design_suggestion as route

    _make_asset(db, "Fortinet FortiGate")
    _make_asset(db, "Cisco Switch")

    result = route(current_user=user, db=db)
    assert result.total_assets == 2
    assert result.matched_assets == 2
    assert len(result.components) > 0
    assert len(result.relationships) > 0
