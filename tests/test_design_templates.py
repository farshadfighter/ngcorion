"""Tests for standard design templates (app/modules/design/templates.py and
DesignService.apply_template): Cisco SAFE-based starting points for a new
Design, instead of an empty canvas.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_design_configuration.py / test_topology.py).
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
from app.models.design import DesignComponent, DesignRelationship
from app.models.user import User
from app.modules.design.service import DesignService
from app.modules.design.templates import (
    SCALES,
    TEMPLATES,
    build_safe_enterprise_campus,
    build_template,
    list_templates,
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
    row = User(username=f"tpl_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


# ======================================================================
# Pure template-generation functions
# ======================================================================

def test_list_templates_returns_the_safe_campus_template():
    templates = list_templates()
    assert len(templates) == 1
    assert templates[0].id == "safe_enterprise_campus"
    assert templates[0].framework == "Cisco SAFE"


@pytest.mark.parametrize("scale", ["small", "medium", "large"])
def test_build_safe_enterprise_campus_relationships_reference_real_components(scale):
    components, relationships = build_safe_enterprise_campus(scale)
    keys = {c["_key"] for c in components}

    # Every _key must be unique (they become dict keys resolving to real ids).
    assert len(keys) == len(components)

    for rel in relationships:
        assert rel["_source"] in keys
        assert rel["_destination"] in keys
        assert rel["_source"] != rel["_destination"]


def test_build_safe_enterprise_campus_scales_access_layer_switch_count():
    small, _ = build_safe_enterprise_campus("small")
    medium, _ = build_safe_enterprise_campus("medium")
    large, _ = build_safe_enterprise_campus("large")

    def access_switch_count(components):
        return sum(1 for c in components if c["_key"].startswith("access_sw"))

    assert access_switch_count(small) == SCALES["small"]["access_switches"]
    assert access_switch_count(medium) == SCALES["medium"]["access_switches"]
    assert access_switch_count(large) == SCALES["large"]["access_switches"]
    assert access_switch_count(small) < access_switch_count(medium) < access_switch_count(large)


def test_build_safe_enterprise_campus_unknown_scale_falls_back_to_medium():
    components, relationships = build_safe_enterprise_campus("not-a-real-scale")
    medium_components, medium_relationships = build_safe_enterprise_campus("medium")
    assert len(components) == len(medium_components)
    assert len(relationships) == len(medium_relationships)


def test_build_safe_enterprise_campus_segments_internet_edge_from_data_center():
    components, relationships = build_safe_enterprise_campus("medium")
    component_types = {c["_key"]: c["component_type"] for c in components}

    # The DMZ/data-center zones must each sit behind their own firewall -
    # no direct link from the internet-facing edge router straight to the
    # data center switch/server, bypassing a firewall.
    direct_links = {(r["_source"], r["_destination"]) for r in relationships}
    direct_links |= {(b, a) for a, b in direct_links}
    assert ("edge_router", "dc_sw") not in direct_links
    assert ("edge_router", "dc_server") not in direct_links
    assert component_types["dc_fw"] == "firewall"
    assert component_types["edge_fw"] == "firewall"


def test_build_template_unknown_template_id_raises():
    with pytest.raises(ValueError):
        build_template("not-a-real-template", "medium")


def test_build_template_dispatches_to_safe_enterprise_campus():
    components, relationships = build_template("safe_enterprise_campus", "small")
    expected_components, expected_relationships = build_safe_enterprise_campus("small")
    assert len(components) == len(expected_components)
    assert len(relationships) == len(expected_relationships)


# ======================================================================
# DesignService.apply_template
# ======================================================================

def test_apply_template_creates_components_and_relationships_on_the_version(db, user):
    design = DesignService.create_design(db, "Campus", None, user.id)
    version = design.versions[0]

    DesignService.apply_template(db, version, "safe_enterprise_campus", "medium")
    db.refresh(version)

    expected_components, expected_relationships = build_safe_enterprise_campus("medium")
    assert len(version.components) == len(expected_components)
    assert len(version.relationships_) == len(expected_relationships)


def test_apply_template_relationships_point_at_real_component_ids(db, user):
    design = DesignService.create_design(db, "Campus", None, user.id)
    version = design.versions[0]

    DesignService.apply_template(db, version, "safe_enterprise_campus", "small")
    db.refresh(version)

    component_ids = {c.id for c in version.components}
    for rel in version.relationships_:
        assert rel.source_component_id in component_ids
        assert rel.destination_component_id in component_ids
        assert rel.design_version_id == version.id


def test_apply_template_preserves_component_type_and_position(db, user):
    design = DesignService.create_design(db, "Campus", None, user.id)
    version = design.versions[0]

    DesignService.apply_template(db, version, "safe_enterprise_campus", "small")
    db.refresh(version)

    firewalls = [c for c in version.components if c.component_type == "firewall"]
    assert len(firewalls) == 2  # edge_fw + dc_fw
    for fw in firewalls:
        assert fw.pos_x is not None
        assert fw.pos_y is not None


def test_apply_template_unknown_template_id_raises_and_leaves_no_rows(db, user):
    design = DesignService.create_design(db, "Campus", None, user.id)
    version = design.versions[0]

    with pytest.raises(ValueError):
        DesignService.apply_template(db, version, "does-not-exist", "medium")

    assert db.query(DesignComponent).filter(DesignComponent.design_version_id == version.id).count() == 0
    assert db.query(DesignRelationship).filter(DesignRelationship.design_version_id == version.id).count() == 0


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_get_design_templates_lists_the_safe_template(db, user):
    from app.modules.design.router import get_design_templates as route

    result = route(current_user=user)
    assert len(result) == len(TEMPLATES)
    assert result[0].id == "safe_enterprise_campus"
    assert result[0].framework == "Cisco SAFE"


def test_route_get_design_template_scales_lists_all_scales(db, user):
    from app.modules.design.router import get_design_template_scales as route

    result = route(current_user=user)
    ids = {s.id for s in result}
    assert ids == set(SCALES.keys())


def test_route_create_design_with_template_id_populates_version_one(db, user):
    from app.modules.design.router import create_design as route
    from app.modules.design.schemas import DesignCreate

    request = DesignCreate(name="Campus", template_id="safe_enterprise_campus", template_scale="small")
    summary = route(request=request, current_user=user, db=db)

    design = DesignService.get_design(db, summary.id)
    version = design.versions[0]
    expected_components, expected_relationships = build_safe_enterprise_campus("small")
    assert len(version.components) == len(expected_components)
    assert len(version.relationships_) == len(expected_relationships)


def test_route_create_design_without_template_id_leaves_version_empty(db, user):
    from app.modules.design.router import create_design as route
    from app.modules.design.schemas import DesignCreate

    request = DesignCreate(name="Blank")
    summary = route(request=request, current_user=user, db=db)

    design = DesignService.get_design(db, summary.id)
    version = design.versions[0]
    assert len(version.components) == 0
    assert len(version.relationships_) == 0


def test_route_create_design_with_unknown_template_id_returns_400(db, user):
    from app.modules.design.router import create_design as route
    from app.modules.design.schemas import DesignCreate

    request = DesignCreate(name="Bad", template_id="not-a-real-template")
    with pytest.raises(HTTPException) as exc_info:
        route(request=request, current_user=user, db=db)
    assert exc_info.value.status_code == 400
