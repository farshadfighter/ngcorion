"""
Global search (app/modules/search): what each kind of result matches (names, addresses, MACs in any
notation, Persian digits, CVE ids, TLS services, findings, users, reports), and that each kind is searched
only with the read permission of its module - reports only among those the user may see.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserPermission, UserRole
from app.models.asset_groups import AssetGroup
from app.models.cve import CveEntry
from app.models.noc import NetworkEndpoint
from app.models.remediation import RemediationItem
from app.models.report import Report
from app.models.software import SoftwareItem
from app.models.tls import TlsEndpoint
from app.modules.search import router as R
from app.modules.search import service as S


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


def _n():
    _seq[0] += 1
    return _seq[0]


def _user(db, role=UserRole.ADMIN, read=()):
    u = User(username=f"srch_{_n()}", email=f"srch{_seq[0]}@corp.example", hashed_password="x", role=role,
             is_active=True)
    db.add(u)
    db.flush()
    for module in read:
        db.add(UserPermission(user_id=u.id, module=module.upper(), can_read=True))
    db.flush()
    return u


def _asset(db, name, ip, **kw):
    t = AssetType(type_name=f"Type {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=name, asset_type_id=t.id, ip_address=ip, **kw)
    db.add(a)
    db.flush()
    return a


def _kinds(out):
    return {g["kind"]: g["items"] for g in out["groups"]}


def test_normalise():
    assert S.normalise("  ۱۰.۲۰.۳۰.۴۰ ") == "10.20.30.40"
    assert S.normalise("علي  كاظمي") == "علی کاظمی"


def test_assets_by_name_address_mac_and_serial(db):
    admin = _user(db)
    a = _asset(db, "fw-searchtest-edge", "10.77.1.1", hostname="edge.corp.local", mac_address="00:1A:2B:3C:4D:5E",
               serial_number="FGT60F-SRCH-001")
    _asset(db, "fw-searchtest-dc", "10.77.1.2")
    ids = lambda q: [i["id"] for i in _kinds(S.search(db, admin, q)).get("assets", [])]  # noqa: E731
    assert ids("searchtest")[:2] and a.id in ids("searchtest")
    assert ids("fw-searchtest-edge")[0] == a.id                       # exact name first
    assert ids("۱۰.۷۷.۱.۱") == [a.id]                                  # Persian digits
    for mac in ("00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E", "001a.2b3c.4d5e", "001a2b3c4d5e", "3c:4d:5e"):
        assert a.id in ids(mac), mac
    assert ids("SRCH-001") == [a.id]
    out = _kinds(S.search(db, admin, "00:1a:2b"))["assets"][0]
    assert out["link"] == f"/assets/inventory/{a.id}" and "00:1A:2B:3C:4D:5E" in out["detail"]
    assert S.search(db, admin, "x")["groups"] == []                   # too short


def test_other_kinds(db):
    admin = _user(db)
    a = _asset(db, "srv-searchkinds", "10.77.2.1")
    db.add(AssetGroup(name="Searchkinds DMZ servers"))
    db.add(SoftwareItem(asset_id=a.id, collector="linux", kind="package", name="searchkinds-openssl", version="3.0",
                        source="distro"))
    db.add(NetworkEndpoint(mac="aa:bb:cc:77:88:99", ip="10.77.2.99", vendor="Searchkinds Cameras Ltd",
                           first_seen_at=datetime.utcnow(), last_seen_at=datetime.utcnow()))
    db.add(CveEntry(cve_id="CVE-2099-77001", description="Searchkinds test flaw", severity="critical",
                    cvss_score=9.8, kev=True))
    db.add(TlsEndpoint(asset_id=a.id, host="10.77.2.1", port=8443, server_name="portal.searchkinds.local",
                       source="manual", first_seen_at=datetime.utcnow()))
    db.add(RemediationItem(key=f"cve:{a.id}:CVE-2099-77001", source="cve", ref="CVE-2099-77001", asset_id=a.id,
                           asset_name=a.asset_name, title="Searchkinds test flaw", severity="critical", status="open",
                           first_seen_at=datetime.utcnow(), last_seen_at=datetime.utcnow(),
                           due_at=datetime.utcnow() + timedelta(days=7), updated_at=datetime.utcnow()))
    db.add(Report(template="cve", title="Searchkinds monthly", code="RPT-2099-0001", formats=["pdf"], params={},
                  created_by=admin.id))
    db.flush()
    k = _kinds(S.search(db, admin, "searchkinds"))
    assert k["groups"][0]["title"] == "Searchkinds DMZ servers" and k["groups"][0]["link"].startswith("/assets/groups?q=")
    assert k["software"][0] == {"title": "searchkinds-openssl", "count": 1,
                                "link": "/assets/software?q=searchkinds-openssl"}
    assert k["devices"][0]["link"].startswith("/noc/unknown-devices?focus=")
    assert k["certificates"][0]["title"] == "portal.searchkinds.local:8443"
    assert k["findings"][0]["link"].startswith("/remediation?item=")
    assert k["reports"][0]["detail"] == "RPT-2099-0001"
    cve = _kinds(S.search(db, admin, "cve-2099-77"))["cves"][0]
    assert cve["title"] == "CVE-2099-77001" and cve["kev"] and cve["link"] == "/cve?cve=CVE-2099-77001"
    assert "cves" not in _kinds(S.search(db, admin, "2099-77"))        # ids only with the CVE prefix
    assert _kinds(S.search(db, admin, "CVE-2099-77001"))["findings"][0]["ref"] == "CVE-2099-77001"
    assert _kinds(S.search(db, admin, "aabb.cc77"))["devices"][0]["title"] == "10.77.2.99"
    assert _kinds(S.search(db, admin, "aabbcc77"))["devices"][0]["title"] == "10.77.2.99"   # bare hex


def test_each_kind_needs_its_read_permission(db):
    admin = _user(db)
    a = _asset(db, "srv-searchperm", "10.77.3.1")
    db.add(Report(template="cve", title="Searchperm report of the admin", formats=["pdf"], params={},
                  created_by=admin.id))
    db.flush()
    nobody = _user(db, UserRole.USER)
    assert S.search(db, nobody, "searchperm")["groups"] == []
    reader = _user(db, UserRole.USER, read=("asset_list", "reports"))
    k = _kinds(S.search(db, reader, "searchperm"))
    assert [i["id"] for i in k["assets"]] == [a.id]
    assert "reports" not in k                     # another user's report stays hidden
    db.add(Report(template="cve", title="Searchperm report of the reader", formats=["pdf"], params={},
                  created_by=reader.id))
    db.flush()
    assert [r["title"] for r in _kinds(S.search(db, reader, "searchperm"))["reports"]] == ["Searchperm report of the reader"]
    assert "users" not in _kinds(S.search(db, reader, reader.username))
    assert _kinds(S.search(db, admin, reader.username))["users"][0]["title"] == reader.username


def test_route_needs_a_signed_in_user():
    route = R.router.routes[0]
    deps = [d.call.__name__ for d in route.dependant.dependencies]
    assert "get_current_user" in deps
