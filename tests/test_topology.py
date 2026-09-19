"""Tests for the Topology module (links CRUD, graph assembly, validation pass).

Needs a migrated PostgreSQL database; each test runs inside a transaction that
is rolled back, so nothing here touches real rows (same pattern as
test_asset_deletion.py).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.topology import TopologyLink
from app.models.user import User
from app.modules.topology.service import TopologyService
from app.modules.topology.schemas import TopologyLinkCreate, TopologyLinkUpdate


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
    row = User(username=f"topo_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, type_name="Router") -> Asset:
    asset_type = AssetType(type_name=f"{type_name}_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(asset_name=f"topo-asset-{_next()}", asset_type_id=asset_type.id)
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def asset_pair(db):
    return _make_asset(db), _make_asset(db, type_name="Switch")


# ======================================================================
# Service: link CRUD
# ======================================================================

def test_create_link_persists_endpoints_and_defaults(db, asset_pair, user):
    a, b = asset_pair
    link = TopologyService.create_link(
        db,
        {
            "source_asset_id": a.id,
            "destination_asset_id": b.id,
            "source_interface": "Gi0/0",
            "destination_interface": "Gi0/1",
            "link_type": "ethernet",
            "speed_mbps": 1000,
            "vlan": None,
            "subnet": None,
            "status": "active",
        },
        user.id,
    )
    assert link.id is not None
    assert link.source_asset_id == a.id
    assert link.destination_asset_id == b.id
    assert link.created_by == user.id


def test_update_link_applies_only_given_fields(db, asset_pair, user):
    a, b = asset_pair
    link = TopologyService.create_link(
        db,
        {"source_asset_id": a.id, "destination_asset_id": b.id, "link_type": "ethernet", "status": "active"},
        user.id,
    )
    updated = TopologyService.update_link(db, link, {"status": "down"})
    assert updated.status == "down"
    assert updated.link_type == "ethernet"  # untouched


def test_delete_link_removes_the_row(db, asset_pair, user):
    a, b = asset_pair
    link = TopologyService.create_link(
        db, {"source_asset_id": a.id, "destination_asset_id": b.id}, user.id
    )
    link_id = link.id
    TopologyService.delete_link(db, link)
    assert db.query(TopologyLink).filter(TopologyLink.id == link_id).first() is None


def test_deleting_an_asset_cascades_its_links(db, asset_pair, user):
    """The link's FKs are ON DELETE CASCADE - it must not survive its asset."""
    a, b = asset_pair
    link = TopologyService.create_link(
        db, {"source_asset_id": a.id, "destination_asset_id": b.id}, user.id
    )
    link_id = link.id
    db.delete(a)
    db.flush()
    assert db.query(TopologyLink).filter(TopologyLink.id == link_id).first() is None


# ======================================================================
# Service: validation pass
# ======================================================================

def test_validate_flags_orphan_and_single_link_assets(db, user):
    orphan = _make_asset(db)
    single = _make_asset(db)
    hub = _make_asset(db)
    redundant_a = _make_asset(db)
    redundant_b = _make_asset(db)

    # single -- hub -- redundant_a -- redundant_b -- hub
    # single: degree 1. hub: degree 3. redundant_a/b: degree 2 each.
    TopologyService.create_link(
        db, {"source_asset_id": single.id, "destination_asset_id": hub.id}, user.id
    )
    TopologyService.create_link(
        db, {"source_asset_id": hub.id, "destination_asset_id": redundant_a.id}, user.id
    )
    TopologyService.create_link(
        db, {"source_asset_id": hub.id, "destination_asset_id": redundant_b.id}, user.id
    )
    TopologyService.create_link(
        db, {"source_asset_id": redundant_a.id, "destination_asset_id": redundant_b.id}, user.id
    )

    findings = TopologyService.validate(db)
    codes_by_asset = {f.asset_id: f.code for f in findings}

    assert codes_by_asset.get(orphan.id) == "orphan_node"
    assert codes_by_asset.get(single.id) == "single_link"
    assert redundant_a.id not in codes_by_asset
    assert redundant_b.id not in codes_by_asset


def test_validate_ignores_planned_links_for_redundancy(db, user):
    """A 'planned' link isn't live cabling yet, so it shouldn't hide a real gap."""
    a = _make_asset(db)
    b = _make_asset(db)
    TopologyService.create_link(
        db, {"source_asset_id": a.id, "destination_asset_id": b.id, "status": "planned"}, user.id
    )

    findings = TopologyService.validate(db)
    codes_by_asset = {f.asset_id: f.code for f in findings}
    assert codes_by_asset.get(a.id) == "orphan_node"
    assert codes_by_asset.get(b.id) == "orphan_node"


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_rejects_self_link(db, asset_pair, user):
    from app.modules.topology.router import create_link as route

    a, _ = asset_pair
    request = TopologyLinkCreate(source_asset_id=a.id, destination_asset_id=a.id)
    with pytest.raises(HTTPException) as exc_info:
        route(request=request, current_user=user, db=db)
    assert exc_info.value.status_code == 400


def test_route_404s_for_missing_source_asset(db, asset_pair, user):
    from app.modules.topology.router import create_link as route

    _, b = asset_pair
    request = TopologyLinkCreate(source_asset_id=2_000_000_000, destination_asset_id=b.id)
    with pytest.raises(HTTPException) as exc_info:
        route(request=request, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_update_404s_for_missing_link(db, user):
    from app.modules.topology.router import update_link as route

    with pytest.raises(HTTPException) as exc_info:
        route(link_id=2_000_000_000, request=TopologyLinkUpdate(status="down"), current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_create_writes_a_topology_log(db, asset_pair, user):
    from app.modules.topology.router import create_link as route
    from app.models.topology_log import TopologyLog

    a, b = asset_pair
    request = TopologyLinkCreate(source_asset_id=a.id, destination_asset_id=b.id)
    link = route(request=request, current_user=user, db=db)

    log = db.query(TopologyLog).filter(TopologyLog.link_id == link.id).first()
    assert log is not None
    assert log.action == "create"


# ======================================================================
# Node position persistence
# ======================================================================

def test_new_asset_has_no_saved_position(db, asset_pair):
    a, _ = asset_pair
    positions = TopologyService.get_positions(db)
    assert a.id not in positions


def test_save_position_creates_a_row(db, asset_pair):
    a, _ = asset_pair
    TopologyService.save_position(db, a.id, 120.5, 340.0)
    positions = TopologyService.get_positions(db)
    assert positions[a.id].pos_x == 120.5
    assert positions[a.id].pos_y == 340.0


def test_save_position_upserts_on_a_second_drag(db, asset_pair):
    a, _ = asset_pair
    TopologyService.save_position(db, a.id, 10, 10)
    TopologyService.save_position(db, a.id, 999, 888)
    positions = TopologyService.get_positions(db)
    assert len(positions) == 1
    assert positions[a.id].pos_x == 999
    assert positions[a.id].pos_y == 888


def test_deleting_an_asset_cascades_its_saved_position(db, asset_pair):
    a, _ = asset_pair
    TopologyService.save_position(db, a.id, 1, 1)
    db.delete(a)
    db.flush()
    assert a.id not in TopologyService.get_positions(db)


def test_route_get_topology_includes_null_position_for_a_never_dragged_node(db, asset_pair, user):
    from app.modules.topology.router import get_topology as route

    a, b = asset_pair
    graph = route(current_user=user, db=db)
    node = next(n for n in graph.nodes if n.id == a.id)
    assert node.pos_x is None
    assert node.pos_y is None


def test_route_get_topology_includes_saved_position(db, asset_pair, user):
    from app.modules.topology.router import get_topology as route

    a, b = asset_pair
    TopologyService.save_position(db, a.id, 55, 66)
    graph = route(current_user=user, db=db)
    node = next(n for n in graph.nodes if n.id == a.id)
    assert node.pos_x == 55
    assert node.pos_y == 66


def test_route_save_position_404s_for_missing_asset(db, user):
    from app.modules.topology.router import save_node_position as route
    from app.modules.topology.schemas import TopologyNodePositionUpdate

    with pytest.raises(HTTPException) as exc_info:
        route(asset_id=2_000_000_000, request=TopologyNodePositionUpdate(pos_x=1, pos_y=1), current_user=user, db=db)
    assert exc_info.value.status_code == 404
