"""Tests for the Design & Configuration modules (designs/versions/components/
relationships/mapping, and configuration generation + apply dispatch).

Needs a migrated PostgreSQL database; each test runs inside a transaction that
is rolled back, so nothing here touches real rows (same pattern as
test_asset_deletion.py / test_topology.py).
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
from app.models.design import ArchitectureDesign, DesignComponent, DesignRelationship
from app.models.configuration import ConfigurationJob, ConfigurationObject
from app.models.user import User
from app.modules.design.service import DesignService
from app.modules.configuration.service import ConfigurationService
from app.modules.configuration.templates import generate_commands


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
    row = User(username=f"dc_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, type_name="Cisco Router") -> Asset:
    asset_type = AssetType(type_name=f"{type_name}_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(asset_name=f"dc-asset-{_next()}", asset_type_id=asset_type.id, ip_address="10.0.0.9")
    db.add(row)
    db.flush()
    return row


# ======================================================================
# Design service
# ======================================================================

def test_create_design_also_creates_version_one(db, user):
    design = DesignService.create_design(db, "Branch Design", "desc", user.id)
    assert design.id is not None
    assert len(design.versions) == 1
    assert design.versions[0].version_number == 1


def test_create_component_and_relationship(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]

    a = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})
    b = DesignService.create_component(db, version, {"component_type": "switch", "label": "SW1"})

    rel = DesignService.create_relationship(
        db, version,
        {
            "source_component_id": a.id,
            "destination_component_id": b.id,
            "source_interface": "Gi0/0",
            "destination_interface": "Gi0/1",
            "link_type": "ethernet",
            "vlan": "10",
            "subnet": None,
        },
    )
    assert rel.id is not None
    assert rel.source_component_id == a.id


def test_delete_component_cascades_its_relationships(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    a = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})
    b = DesignService.create_component(db, version, {"component_type": "switch", "label": "SW1"})
    rel = DesignService.create_relationship(
        db, version, {"source_component_id": a.id, "destination_component_id": b.id}
    )
    rel_id = rel.id

    DesignService.delete_component(db, a)
    assert db.query(DesignRelationship).filter(DesignRelationship.id == rel_id).first() is None


def test_map_and_unmap_component_to_asset(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    component = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})
    asset = _make_asset(db)

    mapping = DesignService.map_component_to_asset(db, component, asset.id, user.id)
    assert mapping.asset_id == asset.id

    DesignService.unmap_component(db, component)
    db.refresh(component)
    assert component.asset_mapping is None


def test_create_version_clones_components_and_relationships(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    v1 = design.versions[0]
    a = DesignService.create_component(db, v1, {"component_type": "router", "label": "R1"})
    b = DesignService.create_component(db, v1, {"component_type": "switch", "label": "SW1"})
    DesignService.create_relationship(
        db, v1, {"source_component_id": a.id, "destination_component_id": b.id, "vlan": "20"}
    )

    v2 = DesignService.create_version(db, design, "cloned", user.id, clone_from=v1)
    assert v2.version_number == 2
    assert len(v2.components) == 2
    assert len(v2.relationships_) == 1
    # Cloned relationship points at the *new* version's components, not v1's.
    cloned_rel = v2.relationships_[0]
    cloned_ids = {c.id for c in v2.components}
    assert cloned_rel.source_component_id in cloned_ids
    assert cloned_rel.destination_component_id in cloned_ids


# ======================================================================
# Configuration templates (pure functions)
# ======================================================================

def test_generate_commands_unsupported_device_type_returns_comment():
    commands = generate_commands(component=None, relationships=[], device_type="linux")
    assert len(commands) == 1
    assert commands[0].startswith("#")


def test_generate_cisco_commands_include_vlan_and_interface(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    a = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})
    b = DesignService.create_component(db, version, {"component_type": "switch", "label": "SW1"})
    rel = DesignService.create_relationship(
        db, version,
        {"source_component_id": a.id, "destination_component_id": b.id, "source_interface": "Gi0/0", "vlan": "30"},
    )
    commands = generate_commands(a, [rel], "cisco")
    joined = "\n".join(commands)
    assert "interface Gi0/0" in joined
    assert "switchport access vlan 30" in joined


# ======================================================================
# Configuration service: job generation
# ======================================================================

def test_generate_job_skips_unmapped_components(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})  # unmapped

    job = ConfigurationService.generate_job(db, version, "job-1", user.id)
    assert job.id is not None
    assert len(job.objects) == 0


def test_generate_job_creates_object_for_mapped_component(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    component = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})
    asset = _make_asset(db, type_name="Cisco Router")
    DesignService.map_component_to_asset(db, component, asset.id, user.id)

    job = ConfigurationService.generate_job(db, version, "job-1", user.id)
    assert len(job.objects) == 1
    obj = job.objects[0]
    assert obj.asset_id == asset.id
    assert obj.device_type == "cisco"
    assert obj.apply_status == "pending"


def test_apply_object_unsupported_device_type_raises(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    component = DesignService.create_component(db, version, {"component_type": "server", "label": "S1"})
    asset = _make_asset(db, type_name="Ubuntu Linux Server")
    DesignService.map_component_to_asset(db, component, asset.id, user.id)

    job = ConfigurationService.generate_job(db, version, "job-1", user.id)
    obj = job.objects[0]
    assert obj.device_type not in ("cisco", "fortinet")

    result = ConfigurationService.apply_object(
        db, obj, username="u", password="p", secret=None, port=22, user_id=user.id
    )
    assert result.apply_status == "failed"
    assert "not supported" in result.apply_output


def test_apply_object_with_no_asset_id_raises_value_error(db, user):
    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    job = ConfigurationService.generate_job(db, version, "empty-job", user.id)
    obj = ConfigurationObject(
        configuration_job_id=job.id, generated_config="interface Gi0/0", device_type="cisco", apply_status="pending"
    )
    db.add(obj)
    db.flush()

    with pytest.raises(ValueError):
        ConfigurationService.apply_object(db, obj, username="u", password="p", secret=None, port=22, user_id=user.id)


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_create_relationship_rejects_self_link(db, user):
    from app.modules.design.router import create_relationship as route
    from app.modules.design.schemas import RelationshipCreate

    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    a = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})

    request = RelationshipCreate(source_component_id=a.id, destination_component_id=a.id)
    with pytest.raises(HTTPException) as exc_info:
        route(version_id=version.id, request=request, current_user=user, db=db)
    assert exc_info.value.status_code == 400


def test_route_map_component_404s_for_missing_asset(db, user):
    from app.modules.design.router import map_component as route
    from app.modules.design.schemas import MapAssetRequest

    design = DesignService.create_design(db, "D", None, user.id)
    version = design.versions[0]
    component = DesignService.create_component(db, version, {"component_type": "router", "label": "R1"})

    with pytest.raises(HTTPException) as exc_info:
        route(component_id=component.id, request=MapAssetRequest(asset_id=2_000_000_000), current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_apply_404s_for_missing_object(db, user):
    from app.modules.configuration.router import apply_object as route
    from app.modules.configuration.schemas import ApplyObjectRequest

    with pytest.raises(HTTPException) as exc_info:
        route(
            object_id=2_000_000_000,
            request=ApplyObjectRequest(ssh_username="u", ssh_password="p"),
            current_user=user, db=db,
        )
    assert exc_info.value.status_code == 404
