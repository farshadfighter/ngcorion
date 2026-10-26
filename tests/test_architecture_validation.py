"""Tests for the Architecture Validation module: the rule engine, the topology checked against
Cisco SAFE (rules/safe.yaml, topology.py, places.py) and the findings workflow.

Needs a migrated PostgreSQL database; each test runs inside a transaction that
is rolled back, so nothing here touches real rows (same pattern as
test_asset_deletion.py / test_topology.py).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.architecture_finding import ArchitectureFinding
from app.models.asset_zone import find_zone
from app.models.risk import RiskZone
from app.models.topology import TopologyCloud, TopologyCloudLink, TopologyLink
from app.models.user import User
from app.modules.architecture_validation.engine import (
    evaluate_condition,
    run_rules,
    load_rules,
    RuleConditionError,
)
from app.modules.architecture_validation.places import place_from_name, place_of
from app.modules.architecture_validation.service import ArchitectureValidationService


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
    row = User(username=f"av_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


_types = {}


def _make_asset(db, kind: str = "Server", zone: str = None, **overrides) -> Asset:
    """An asset of a type named `kind` ("Firewall", "Switch", "Server", "ISP Link", ...) in `zone`."""
    name = f"{kind} {_next()}"
    asset_type = AssetType(type_name=name, category="network")
    db.add(asset_type)
    db.flush()
    if zone and find_zone(db, zone) is None:
        db.add(RiskZone(name=zone, score=50, status="active"))
        db.flush()
    defaults = dict(asset_name=f"av-{kind.split()[0].lower()}-{_seq[0]}", asset_type_id=asset_type.id,
                    asset_role=zone)
    defaults.update(overrides)
    row = Asset(**defaults)
    db.add(row)
    db.flush()
    return row


def _link(db, a, b, status="active", a_if=None, b_if=None):
    db.add(TopologyLink(source_asset_id=a.id, destination_asset_id=b.id, status=status,
                        source_interface=a_if, destination_interface=b_if))
    db.flush()


def _found(db) -> dict:
    """{(rule code, asset name): evidence} of one analysis run."""
    return {(f.rule_code, f.asset_name): f.evidence for f in ArchitectureValidationService.analyze(db)}


INTERNET, DMZ, DC, USERS, MGMT = "Internet / Public", "DMZ", "Internal Server Zone", "User Network", "Management"


# ======================================================================
# Engine: condition evaluation
# ======================================================================

def test_evaluate_condition_basic_comparison():
    assert evaluate_condition("links == 0", {"links": 0}) is True
    assert evaluate_condition("links == 0", {"links": 2}) is False


def test_evaluate_condition_boolean_ops():
    ctx = {"is_critical": True, "in_topology": False}
    assert evaluate_condition("is_critical and not in_topology", ctx) is True
    assert evaluate_condition("is_critical and in_topology", ctx) is False


def test_evaluate_condition_in_operator():
    assert evaluate_condition('place in ("campus", "guest")', {"place": "guest"}) is True
    assert evaluate_condition('place in ("campus", "guest")', {"place": "data_center"}) is False


def test_evaluate_condition_rejects_unknown_name():
    with pytest.raises(RuleConditionError):
        evaluate_condition("nonexistent_field == 1", {})


def test_evaluate_condition_rejects_arbitrary_code():
    """The whole point of the AST walker: no function calls, no imports."""
    with pytest.raises(RuleConditionError):
        evaluate_condition("__import__('os').system('echo hi')", {})


def test_load_rules_are_all_unique_and_valid():
    rules = load_rules()
    codes = [r["code"] for r in rules]
    assert len(codes) == len(set(codes)), "duplicate rule codes"
    for rule in rules:
        assert rule["severity"] in ("low", "medium", "high")
        assert rule["category"] in ("segmentation", "threat_defense", "management", "availability", "visibility")
        assert rule.get("place") in ("edge", "data_center", "storage", "campus", "branch", "management", "lab", "wan",
                                     "cloud", None)
        assert bool(rule.get("evidence")) == bool(rule.get("evidence_label"))
        # Every condition must at least parse.
        import ast as _ast
        _ast.parse(rule["condition"], mode="eval")


def test_every_rule_reads_only_topology_facts(db):
    """Every name a condition uses is a fact the topology gives (no inventory, backup or audit)."""
    import ast as _ast
    from app.modules.architecture_validation.topology import load
    asset = _make_asset(db, "Server", DC)
    context = ArchitectureValidationService.build_asset_context(asset, load(db).facts({})[asset.id])
    for rule in load_rules():
        names = {n.id for n in _ast.walk(_ast.parse(rule["condition"], mode="eval")) if isinstance(n, _ast.Name)}
        assert names <= set(context), (rule["code"], names - set(context))
        assert rule.get("evidence") is None or rule["evidence"] in context


def test_run_rules_returns_only_matching_rules():
    rules = [
        {"code": "X-1", "title": "t", "severity": "low", "condition": "flag"},
        {"code": "X-2", "title": "t", "severity": "low", "condition": "not flag"},
    ]
    findings = run_rules({"flag": True}, rules)
    assert [f["code"] for f in findings] == ["X-1"]


# ======================================================================
# Places in the network
# ======================================================================

def test_a_zone_says_its_place():
    assert [place_from_name(n) for n in (INTERNET, DMZ, DC, USERS, MGMT, "Isolated / Lab", "Guest Wi-Fi",
                                         "Data Center", "Edge", "Branch Tehran", "Unknown")] == [
        "internet", "edge", "data_center", "campus", "management", "lab", "guest", "data_center", "edge",
        "branch", None]
    assert place_of(RiskZone(name="Core", place="data_center")) == "data_center"     # chosen wins
    assert place_of(RiskZone(name="DMZ", place=None)) == "edge"


def test_a_place_chosen_on_the_zone(db):
    from app.modules.assets.service import AssetService
    zone = AssetService.create_zone(db, {"zone_name": "Core Block", "score": 40, "place": "data_center"})
    assert (zone.place, zone.place_in_effect) == ("data_center", "data_center")
    zone, _ = AssetService.update_zone(db, zone.id, {"place": ""})          # back to the name: says nothing
    assert (zone.place, zone.place_in_effect) == (None, None)
    srv = _make_asset(db, "Server", "Core Block")
    sw = _make_asset(db, "Switch", USERS)
    _link(db, sw, srv)
    assert ("AV-141", srv.asset_name) in _found(db)
    AssetService.update_zone(db, zone.id, {"place": "data_center"})
    assert ("AV-104", srv.asset_name) in _found(db)


# ======================================================================
# The topology against Cisco SAFE
# ======================================================================

def test_a_flat_network_is_reachable_from_the_internet(db):
    isp = _make_asset(db, "ISP Link", INTERNET)
    core = _make_asset(db, "Switch", USERS)
    srv = _make_asset(db, "Server", DC)
    _link(db, isp, core)
    _link(db, core, srv)
    found = _found(db)
    assert found[("AV-101", srv.asset_name)] == f"{isp.asset_name} -> {core.asset_name} -> {srv.asset_name}"
    assert ("AV-104", srv.asset_name) in found                     # users reach the server too
    assert found[("AV-121", core.asset_name)] == f"{isp.asset_name} - {core.asset_name}"
    assert ("AV-132", srv.asset_name) in found                     # on one switch


def test_a_firewall_filters(db):
    isp = _make_asset(db, "ISP Link", INTERNET)
    fw = _make_asset(db, "Firewall", DMZ)
    core = _make_asset(db, "Switch", USERS)
    srv = _make_asset(db, "Server", DC)
    for a, b in ((isp, fw), (fw, core), (fw, srv)):
        _link(db, a, b)
    found = _found(db)
    assert not [k for k in found if k[0] in ("AV-101", "AV-104")]
    assert ("AV-120", fw.asset_name) in found                      # but it is the only one

    fw2 = _make_asset(db, "Firewall", DMZ)
    for a, b in ((isp, fw2), (fw2, core), (fw2, srv)):
        _link(db, a, b)
    assert ("AV-120", fw.asset_name) not in _found(db)


def test_the_dmz_and_guests_must_not_reach_inside(db):
    web = _make_asset(db, "Server", DMZ)
    ap = _make_asset(db, "Access Point", "Guest")
    core = _make_asset(db, "Switch", USERS)
    db_srv = _make_asset(db, "Server", DC)
    jump = _make_asset(db, "Server", MGMT)
    for a in (web, ap, db_srv, jump):
        _link(db, a, core)
    found = _found(db)
    assert found[("AV-102", db_srv.asset_name)] == f"{web.asset_name} -> {core.asset_name} -> {db_srv.asset_name}"
    assert ("AV-103", db_srv.asset_name) in found and ("AV-103", web.asset_name) in found
    assert ("AV-105", jump.asset_name) in found


def test_a_single_point_of_failure(db):
    core = _make_asset(db, "Switch", USERS)
    core2 = _make_asset(db, "Switch", USERS)
    dist = _make_asset(db, "Switch", DC)
    access = _make_asset(db, "Switch", DC)
    srv = _make_asset(db, "Server", DC)
    _link(db, core, core2)
    _link(db, core, dist)
    _link(db, core2, dist)
    _link(db, dist, access)
    _link(db, access, srv)
    found = _found(db)
    assert found[("AV-130", dist.asset_name)] == ", ".join(sorted([access.asset_name, srv.asset_name]))
    assert ("AV-130", core.asset_name) not in found                # core2 is there when core fails
    assert ("AV-134", access.asset_name) in found                  # one uplink


def test_placement_links_down_and_what_cannot_be_checked(db):
    sw = _make_asset(db, "Switch", USERS)
    srv = _make_asset(db, "Server", USERS)                         # a server among users
    pc = _make_asset(db, "Workstation", DC)                        # a PC in the data center
    lonely = _make_asset(db, "Switch", USERS)
    nowhere = _make_asset(db, "Server")
    _link(db, sw, srv)
    _link(db, sw, pc)
    _link(db, sw, nowhere)
    _link(db, sw, lonely, status="down", a_if="Gi1/0/1", b_if="Gi0/1")
    found = _found(db)
    assert ("AV-111", srv.asset_name) in found and ("AV-112", pc.asset_name) in found
    assert found[("AV-135", sw.asset_name)] == f"{sw.asset_name} Gi1/0/1 - {lonely.asset_name} Gi0/1"
    assert ("AV-141", nowhere.asset_name) in found
    assert ("AV-140", lonely.asset_name) not in found              # its link is down, not missing
    gone = _make_asset(db, "Server", USERS)                        # LLDP no longer reports its link
    db.add(TopologyLink(source_asset_id=sw.id, destination_asset_id=gone.id, origin="lldp",
                        missing_since=datetime(2026, 10, 1)))
    db.flush()
    assert ("AV-135", sw.asset_name) in _found(db)
    assert (sw.asset_name + " - " + gone.asset_name) in _found(db)[("AV-135", sw.asset_name)]
    alone = _make_asset(db, "Router", USERS)
    assert ("AV-140", alone.asset_name) in _found(db)


def test_only_topology_findings(db):
    """An asset with no IP, owner, backup or audit, in a sound place, has nothing to fix here."""
    fw = _make_asset(db, "Firewall", DMZ)
    fw2 = _make_asset(db, "Firewall", DMZ)
    srv = _make_asset(db, "Server", DC, ip_address=None)
    _link(db, fw, srv)
    _link(db, fw2, srv)
    assert not [k for k in _found(db) if k[1] == srv.asset_name]


def test_analyze_does_not_recreate_resolved_findings(db, user):
    srv = _make_asset(db, "Server", DC)
    first = [f for f in ArchitectureValidationService.analyze(db) if f.asset_name == srv.asset_name]
    finding = next(f for f in first if f.rule_code == "AV-140")
    ArchitectureValidationService.resolve_finding(db, finding, "accepted", user.id)
    again = [f for f in ArchitectureValidationService.analyze(db) if f.asset_name == srv.asset_name]
    assert all(f.rule_code != "AV-140" for f in again)
    assert db.get(ArchitectureFinding, finding.id) is not None


def test_retired_checks_go(db, user):
    srv = _make_asset(db, "Server", DC)
    old = ArchitectureFinding(rule_code="AV-021", title="Asset has never been audited", severity="medium",
                              asset_id=srv.id, asset_name=srv.asset_name, status="accepted")
    db.add(old)
    db.flush()
    ArchitectureValidationService.analyze(db)
    assert db.query(ArchitectureFinding).filter(ArchitectureFinding.rule_code == "AV-021").count() == 0


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_lists_the_rules(user):
    from app.modules.architecture_validation.router import list_rules
    rules = list_rules(current_user=user)
    assert rules[0].code == "AV-101" and rules[0].evidence_label == "Unfiltered path"


def test_route_accept_404s_for_missing_finding(db, user):
    from app.modules.architecture_validation.router import accept_finding as route

    with pytest.raises(HTTPException) as exc_info:
        route(finding_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_accept_marks_status(db, user):
    from app.modules.architecture_validation.router import accept_finding as route

    _make_asset(db, "Router")
    findings = ArchitectureValidationService.analyze(db)
    finding = findings[0]

    result = route(finding_id=finding.id, current_user=user, db=db)
    assert result.status == "accepted"
    assert result.resolved_at is not None


def test_every_rule_text_has_a_persian_translation():
    """Titles, recommendations and evidence labels are shown translated (front/src/i18n/backendText.js)."""
    import json
    root = PROJECT_ROOT / "front" / "src" / "i18n"
    registered = (root / "backendText.js").read_text()
    persian = {}
    for path in (root / "locales" / "fa").glob("*.json"):       # a text used elsewhere too sits in one file
        persian.update(json.loads(path.read_text()))
    for rule in load_rules():
        for key in ("title", "recommendation", "evidence_label"):
            text = rule.get(key)
            if text:
                assert f"msg({json.dumps(text, ensure_ascii=False)})" in registered, (rule["code"], key)
                assert persian.get(text), (rule["code"], key)


# ======================================================================
# Storage: SAN, iSCSI, NFS (AV-150 to AV-152)
# ======================================================================

STORAGE_NET = "Storage Network (SAN)"


def test_the_storage_network_is_a_place():
    assert place_from_name("Storage Network (SAN)") == "storage"
    assert place_from_name("iSCSI VLAN") == "storage"
    assert place_from_name("NAS") == "storage"
    assert place_from_name("Internal Server Zone") == "data_center"


def test_storage_reached_by_users_is_one_finding(db):
    """Users reach a NAS through switches only: AV-150 with the path, not the general AV-104 too."""
    pc = _make_asset(db, "Workstation", USERS)
    access = _make_asset(db, "Switch", USERS)
    nas = _make_asset(db, "Synology NAS", DC)
    _link(db, pc, access)
    _link(db, access, nas)
    found = _found(db)
    assert found[("AV-150", nas.asset_name)] == f"{access.asset_name} -> {nas.asset_name}"    # from the user network
    assert ("AV-104", nas.asset_name) not in found
    # and on one switch: a single path (not the general AV-132)
    assert ("AV-152", nas.asset_name) in found and ("AV-132", nas.asset_name) not in found


def test_storage_behind_the_data_center_firewall_on_two_fabrics_is_clean(db):
    pc = _make_asset(db, "Workstation", USERS)
    access = _make_asset(db, "Switch", USERS)
    dc_fw = _make_asset(db, "Firewall", DC)
    san_a = _make_asset(db, "Switch", STORAGE_NET)
    san_b = _make_asset(db, "Switch", STORAGE_NET)
    array = _make_asset(db, "NetApp Storage", STORAGE_NET)
    host = _make_asset(db, "Hypervisor", DC)
    for a, b in ((pc, access), (access, dc_fw), (dc_fw, host), (host, san_a), (host, san_b),
                 (array, san_a), (array, san_b)):
        _link(db, a, b)
    found = _found(db)
    assert not [k for k in found if k[0] in ("AV-150", "AV-151", "AV-152") and k[1] == array.asset_name]


def test_storage_in_a_user_network(db):
    nas = _make_asset(db, "QNAP NAS", USERS)
    sw1, sw2 = _make_asset(db, "Switch", USERS), _make_asset(db, "Switch", USERS)
    _link(db, nas, sw1)
    _link(db, nas, sw2)
    found = _found(db)
    assert ("AV-151", nas.asset_name) in found and ("AV-111", nas.asset_name) not in found


# ======================================================================
# External networks (clouds) drawn on the topology
# ======================================================================

def _cloud(db, kind, label=None):
    row = TopologyCloud(kind=kind, label=label or f"{kind} {_next()}")
    db.add(row)
    db.flush()
    return row


def _cloud_link(db, cloud, asset, status="active", interface=None):
    db.add(TopologyCloudLink(cloud_id=cloud.id, asset_id=asset.id, status=status, interface=interface))
    db.flush()


def test_the_internet_cloud_is_the_outside(db):
    """A drawn Internet cloud works like an Internet asset: a path to a host, and the only uplink."""
    internet = _cloud(db, "internet", "Internet")
    core = _make_asset(db, "Switch", USERS)
    srv = _make_asset(db, "Server", DC)
    _cloud_link(db, internet, core)
    _link(db, core, srv)
    found = _found(db)
    assert found[("AV-101", srv.asset_name)] == f"Internet -> {core.asset_name} -> {srv.asset_name}"
    assert found[("AV-121", core.asset_name)] == f"Internet - {core.asset_name}"
    assert not [k for k in found if k[1] == "Internet"]             # a cloud has no findings


def test_an_internet_cloud_behind_two_edge_firewalls(db):
    internet = _cloud(db, "internet", "Internet")
    fw1, fw2 = _make_asset(db, "Firewall", DMZ), _make_asset(db, "Firewall", DMZ)
    srv = _make_asset(db, "Server", DC)
    for fw in (fw1, fw2):
        _cloud_link(db, internet, fw)
        _link(db, fw, srv)
    found = _found(db)
    assert not [k for k in found if k[0] in ("AV-101", "AV-120", "AV-121")]


def test_mpls_on_a_switch_and_a_single_wan_link(db):
    mpls = _cloud(db, "mpls", "MPLS")
    sw = _make_asset(db, "Switch", USERS)
    _cloud_link(db, mpls, sw)
    found = _found(db)
    assert found[("AV-161", sw.asset_name)] == "MPLS"
    assert found[("AV-162", sw.asset_name)] == f"MPLS - {sw.asset_name}"
    assert not [k for k in found if k[0] in ("AV-101", "AV-121")]    # the WAN is not the Internet

    router = _make_asset(db, "Router", USERS)
    lte = _cloud(db, "sdwan", "SD-WAN")
    _cloud_link(db, lte, router)
    found = _found(db)
    assert ("AV-161", router.asset_name) not in found               # a router ends a WAN circuit
    assert not [k for k in found if k[0] == "AV-162"]               # two WAN links now


def test_a_public_cloud_reaches_the_data_center_without_a_firewall(db):
    aws = _cloud(db, "public_cloud", "AWS")
    router = _make_asset(db, "Router", DC)
    srv = _make_asset(db, "Server", DC)
    _cloud_link(db, aws, router)
    _link(db, router, srv)
    found = _found(db)
    assert found[("AV-160", srv.asset_name)] == f"AWS -> {router.asset_name} -> {srv.asset_name}"
    assert ("AV-101", srv.asset_name) not in found                  # a cloud is not the Internet

    fw = _make_asset(db, "Firewall", DC)
    db.query(TopologyLink).filter(TopologyLink.source_asset_id == router.id).delete()
    _link(db, router, fw)
    _link(db, fw, srv)
    assert ("AV-160", srv.asset_name) not in _found(db)


def test_a_planned_or_down_cloud_link(db):
    internet = _cloud(db, "internet", "Internet")
    fw = _make_asset(db, "Firewall", DMZ)
    _cloud_link(db, internet, fw, status="planned")
    assert ("AV-121", fw.asset_name) not in _found(db)              # not there yet
    db.query(TopologyCloudLink).delete()
    _cloud_link(db, internet, fw, status="down", interface="port1")
    found = _found(db)
    assert found[("AV-135", fw.asset_name)] == f"Internet - {fw.asset_name} port1"


def test_wan_type_names_are_the_wan_not_the_internet(db):
    wan = _make_asset(db, "WAN Link")
    sw = _make_asset(db, "Switch", USERS)
    srv = _make_asset(db, "Server", DC)
    _link(db, wan, sw)
    _link(db, sw, srv)
    found = _found(db)
    assert ("AV-101", srv.asset_name) not in found
    assert ("AV-161", sw.asset_name) in found
