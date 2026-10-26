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

import importlib

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
# Hosted-on edges (computed, not persisted)
# ======================================================================

def test_get_hosted_edges_returns_one_entry_per_hosted_asset(db):
    server = _make_asset(db)
    vm = _make_asset(db)
    vm.hosted_on_asset_id = server.id
    vm.hosted_vlan = "110"
    db.flush()

    edges = TopologyService.get_hosted_edges(db)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["source_asset_id"] == server.id
    assert edge["destination_asset_id"] == vm.id
    assert edge["link_type"] == "hosted"
    assert edge["vlan"] == "110"
    assert edge["id"] == -vm.id  # never collides with a real (positive) TopologyLink id


def test_get_hosted_edges_empty_when_no_asset_is_hosted(db):
    _make_asset(db)
    assert TopologyService.get_hosted_edges(db) == []


def test_validate_does_not_flag_hosted_asset_as_orphan(db):
    """A VM with only a hosted-on relationship (no real cabling) must not be
    reported as a fully disconnected orphan_node - it IS connected, just not
    by a cable."""
    server = _make_asset(db)
    vm = _make_asset(db)
    vm.hosted_on_asset_id = server.id
    db.flush()

    findings = TopologyService.validate(db)
    codes_by_asset = {f.asset_id: f.code for f in findings}
    assert codes_by_asset.get(vm.id) != "orphan_node"


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


def test_route_get_topology_includes_hosted_edge(db, asset_pair, user):
    from app.modules.topology.router import get_topology as route

    server, vm = asset_pair
    vm.hosted_on_asset_id = server.id
    vm.hosted_vlan = "42"
    db.flush()

    graph = route(current_user=user, db=db)
    hosted = [l for l in graph.links if l.link_type == "hosted"]
    assert len(hosted) == 1
    assert hosted[0].source_asset_id == server.id
    assert hosted[0].destination_asset_id == vm.id
    assert hosted[0].vlan == "42"


def test_route_save_position_404s_for_missing_asset(db, user):
    from app.modules.topology.router import save_node_position as route
    from app.modules.topology.schemas import TopologyNodePositionUpdate

    with pytest.raises(HTTPException) as exc_info:
        route(asset_id=2_000_000_000, request=TopologyNodePositionUpdate(pos_x=1, pos_y=1), current_user=user, db=db)
    assert exc_info.value.status_code == 404


# ======================================================================
# External networks (clouds): drawn on the canvas, not assets
# ======================================================================

def test_cloud_create_link_graph_and_delete(db, asset_pair, user):
    from app.models.topology import TopologyCloud, TopologyCloudLink
    from app.models.topology_log import TopologyLog
    R = importlib.import_module("app.modules.topology.router")      # the package's `router` is the APIRouter
    from app.modules.topology.schemas import TopologyCloudIn, TopologyCloudLinkIn

    a, _ = asset_pair
    assets_before = db.query(Asset).count()
    cloud = R.create_cloud(TopologyCloudIn(kind="mpls", label=" MPLS - TCI ", provider="TCI"), current_user=user,
                           db=db)
    assert (cloud.kind, cloud.label, cloud.provider) == ("mpls", "MPLS - TCI", "TCI")
    assert db.query(Asset).count() == assets_before                  # not inventory, not licensed
    link = R.create_cloud_link(TopologyCloudLinkIn(cloud_id=cloud.id, asset_id=a.id, interface="Gi0/0/0",
                                                   circuit_id="TCI-1234", speed_mbps=100),
                               current_user=user, db=db)
    assert link.status == "active"

    graph = R.get_topology(current_user=user, db=db)
    assert [(c.id, c.kind) for c in graph.clouds if c.id == cloud.id] == [(cloud.id, "mpls")]
    assert [(l.cloud_id, l.asset_id, l.interface) for l in graph.cloud_links if l.id == link.id] == \
        [(cloud.id, a.id, "Gi0/0/0")]

    R.update_cloud_link(link.id, TopologyCloudLinkIn(status="down"), current_user=user, db=db)
    assert db.get(TopologyCloudLink, link.id).status == "down"
    R.update_cloud(cloud.id, TopologyCloudIn(pos_x=10, pos_y=20), current_user=user, db=db)
    R.update_cloud(cloud.id, TopologyCloudIn(label="MPLS"), current_user=user, db=db)
    actions = [r.action for r in db.query(TopologyLog).filter(TopologyLog.action.like("cloud%"))
               .order_by(TopologyLog.id)]
    assert actions[-4:] == ["cloud.create", "cloud_link.create", "cloud_link.update", "cloud.update"]  # a drag: none

    R.delete_cloud(cloud.id, current_user=user, db=db)
    assert db.get(TopologyCloud, cloud.id) is None
    assert db.query(TopologyCloudLink).filter(TopologyCloudLink.cloud_id == cloud.id).count() == 0


def test_cloud_routes_refuse_bad_input(db, asset_pair, user):
    from pydantic import ValidationError
    R = importlib.import_module("app.modules.topology.router")      # the package's `router` is the APIRouter
    from app.modules.topology.schemas import TopologyCloudIn, TopologyCloudLinkIn

    a, _ = asset_pair
    with pytest.raises(HTTPException) as exc:
        R.create_cloud(TopologyCloudIn(kind="internet", label="  "), current_user=user, db=db)
    assert exc.value.status_code == 422
    with pytest.raises(ValidationError):
        TopologyCloudIn(kind="moon", label="x")
    with pytest.raises(ValidationError):
        TopologyCloudIn(kind="wan", label="a\nb")
    with pytest.raises(HTTPException) as exc:
        R.create_cloud_link(TopologyCloudLinkIn(cloud_id=2_000_000_000, asset_id=a.id), current_user=user, db=db)
    assert exc.value.status_code == 404
    cloud = R.create_cloud(TopologyCloudIn(kind="internet", label="Internet"), current_user=user, db=db)
    with pytest.raises(HTTPException) as exc:
        R.create_cloud_link(TopologyCloudLinkIn(cloud_id=cloud.id, asset_id=2_000_000_000), current_user=user, db=db)
    assert exc.value.status_code == 404
    for call in (lambda: R.update_cloud(2_000_000_000, TopologyCloudIn(label="x"), current_user=user, db=db),
                 lambda: R.delete_cloud_link(2_000_000_000, current_user=user, db=db)):
        with pytest.raises(HTTPException) as exc:
            call()
        assert exc.value.status_code == 404


def test_cloud_routes_need_topology_write_and_delete(db, user):
    from fastapi.routing import APIRoute
    from app.models.user_permission import UserPermission
    R = importlib.import_module("app.modules.topology.router")      # the package's `router` is the APIRouter

    db.add(UserPermission(user_id=user.id, module="topology", can_read=True, can_write=True, can_delete=False))
    db.flush()
    routes = {(r.path, m): r for r in R.router.routes if isinstance(r, APIRoute) for m in r.methods}
    prefix = R.router.prefix
    for (path, method), allowed in (((f"{prefix}/clouds", "POST"), True), ((f"{prefix}/clouds/{{cloud_id}}", "PATCH"), True),
                                    ((f"{prefix}/clouds/{{cloud_id}}", "DELETE"), False),
                                    ((f"{prefix}/cloud-links", "POST"), True),
                                    ((f"{prefix}/cloud-links/{{link_id}}", "DELETE"), False)):
        route = routes.get((path, method)) or routes[(path.removeprefix(prefix), method)]
        checks = [d.call for d in route.dependant.dependencies
                  if getattr(d.call, "__qualname__", "").startswith("require_permission")]
        assert checks, path
        if allowed:
            assert checks[0](current_user=user, db=db) is user
        else:
            with pytest.raises(HTTPException) as exc:
                checks[0](current_user=user, db=db)
            assert exc.value.status_code == 403
