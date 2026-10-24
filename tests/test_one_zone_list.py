"""
One list of network zones (app/models/asset_zone.py).

Asked from the server: a zone set in Asset List ("Data Center", a new "Edge") was not seen by Risk and the
modules reading the risk zone (asset groups, alert rules, report scope, dashboards). There is one list now,
and an asset's zone is the same wherever it is set or read.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import date

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType
from app.models.asset_zone import find_zone, zone_key
from app.models.risk import AssetRiskProfile, AssetRiskScore, RiskZone
from app.modules.asset_groups.groups import rule_member_ids
from app.modules.assets.service import AssetService
from app.modules.risk.service import risk_calculation_service


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _asset(db, **kw):
    _seq[0] += 1
    t = AssetType(type_name=f"Zone type {_seq[0]}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"zone-asset-{_seq[0]}", asset_type_id=t.id, ip_address=f"10.77.0.{_seq[0] % 250 + 1}", **kw)
    db.add(a)
    db.flush()
    return a


def _profile(db, asset):
    return db.query(AssetRiskProfile).filter(AssetRiskProfile.asset_id == asset.id).one_or_none()


@pytest.fixture
def edge(db):
    zone = AssetService.create_zone(db, {"zone_name": "Edge", "description": "Branch edge", "score": 70})
    return zone


def test_names_match_whatever_their_spelling():
    assert zone_key("Internet / Public") == zone_key("internet-public") == zone_key("External")
    assert zone_key("Internal") == zone_key("Internal Server Zone")


def test_a_zone_set_in_asset_list_is_the_risk_zone(db, edge):
    asset = _asset(db, asset_role="edge")
    assert asset.asset_role == "Edge"                               # the zone's own name
    profile = _profile(db, asset)
    assert (profile.zone_id, profile.zone_is_default) == (edge.id, False)

    score = risk_calculation_service.calculate(asset.id, db, trigger_type="test")
    row = db.query(AssetRiskScore).filter(AssetRiskScore.id == score.id).one()
    assert (row.zone_id, row.zone_name, float(row.zone_score)) == (edge.id, "Edge", 70.0)

    # Asset groups (and alert rules, report scope) select by the same zone
    assert rule_member_ids(db, [{"field": "zone", "op": "eq", "value": edge.id}]) == [asset.id]


def test_a_zone_set_in_risk_shows_in_asset_list(db, edge):
    asset = _asset(db, asset_role="DMZ")
    profile = _profile(db, asset)
    profile.zone_id = edge.id
    db.flush()
    db.refresh(asset)
    assert asset.asset_role == "Edge"


def test_renaming_a_zone_renames_it_on_its_assets(db, edge):
    asset = _asset(db, asset_role="Edge")
    AssetService.update_zone(db, edge.id, {"zone_name": "Branch Edge"})
    db.refresh(asset)
    assert asset.asset_role == "Branch Edge"


def test_editing_an_asset(db, edge):
    asset = _asset(db, last_audit_date=date(2026, 1, 5))
    updated, changes = AssetService.update_asset(db, asset.id, {"asset_role": "Edge"})
    assert _profile(db, updated).zone_id == edge.id
    assert [c["field"] for c in changes] == ["asset_role"]
    assert updated.last_audit_date == date(2026, 1, 5)              # an edit is not an audit

    with pytest.raises(ValueError, match="Data Hall is not a network zone"):
        AssetService.update_asset(db, asset.id, {"asset_role": "Data Hall"})

    AssetService.update_asset(db, asset.id, {"asset_role": None})   # out of any zone
    profile = _profile(db, asset)
    assert (asset.asset_role, profile.zone_id, profile.zone_is_default) == (None, None, True)


def test_zones_of_the_list(db, edge):
    settings = risk_calculation_service._load_settings(db)
    plain = AssetService.create_zone(db, {"zone_name": "Data Center"})
    assert float(plain.score) == float(settings["unknown_zone_score"])
    with pytest.raises(ValueError, match="already exists"):
        AssetService.create_zone(db, {"zone_name": "data-center"})
    assert {"Edge", "Data Center", "DMZ"} <= {z.zone_name for z in AssetService.get_all_zones(db)}

    _asset(db, asset_role="Edge")
    with pytest.raises(ValueError, match="assigned assets"):
        AssetService.delete_zone(db, edge.id)
    assert AssetService.delete_zone(db, plain.id) is True
    assert find_zone(db, "Data Center") is None
    assert db.get(RiskZone, edge.id) is not None


def test_excel_import_names_a_zone(db, edge):
    from io import BytesIO

    from openpyxl import Workbook

    from app.models import User
    from app.utils.excel_utils import import_assets_from_excel
    user = User(username=f"zone_import_{_seq[0]}", hashed_password="x")
    db.add(user)
    t = AssetType(type_name="Zone import type", category="server")
    db.add(t)
    db.flush()
    wb = Workbook()
    ws = wb.active
    ws.title = "Overview"
    ws.append(["Asset Name", "Hostname", "Type", "Network Zone", "Manufacturer", "Model"])
    ws.append(["zone-xl-1", None, t.type_name, "edge", None, None])
    ws.append(["zone-xl-2", None, t.type_name, "Data Hall", None, None])
    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    results = import_assets_from_excel(buf, db, user)
    assert results["created"] == 2
    assert results["errors"] == ["Row 3: Data Hall is not a network zone"]
    first = db.query(Asset).filter(Asset.asset_name == "zone-xl-1").one()
    assert (first.asset_role, _profile(db, first).zone_id) == ("Edge", edge.id)
    assert db.query(Asset).filter(Asset.asset_name == "zone-xl-2").one().asset_role is None


def test_scores_left_on_an_old_zone_are_recalculated(db, edge):
    """A zone changed without a recalculation (the zone lists merged by a migration) is caught up at startup."""
    from app.modules.assets.overview360 import _risk
    from app.modules.risk.zone_rescore import rescore_stale_zones, stale_zone_assets
    asset = _asset(db, asset_role="DMZ")
    risk_calculation_service.calculate(asset.id, db, trigger_type="test")
    db.query(AssetRiskProfile).filter(AssetRiskProfile.asset_id == asset.id).update({"zone_id": edge.id})
    db.query(Asset).filter(Asset.id == asset.id).update({"asset_role": "Edge"})
    db.expire_all()
    assert _risk(db, asset)["zone"] == "Edge"                       # Asset 360 shows the zone it is in
    assert asset.id in stale_zone_assets(db)
    assert rescore_stale_zones(db) >= 1
    row = db.query(AssetRiskScore).filter(AssetRiskScore.asset_id == asset.id).one()
    assert (row.zone_id, row.zone_name) == (edge.id, "Edge")
    assert asset.id not in stale_zone_assets(db)
