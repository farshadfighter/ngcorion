"""
The assets overview (app/modules/dashboard/assets_overview.py): totals and new assets, missing details
with the asset-list filter that shows them, breakdowns with their links and an "other" row, coverage of
end-of-life data, unknown devices only with NOC access, and the route's permission.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserPermission, UserRole
from app.models.noc import NetworkEndpoint
from app.models.risk import AssetRiskProfile, RiskZone
from app.modules.dashboard import assets_overview as A

NOW = datetime(2099, 6, 1, 12, 0)


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
    u = User(username=f"amo_{_n()}", email=f"amo{_seq[0]}@corp.example", hashed_password="x", role=role,
             is_active=True)
    db.add(u)
    db.flush()
    for module in read:
        db.add(UserPermission(user_id=u.id, module=module.upper(), can_read=True))
    db.flush()
    return u


def _type(db, name=None):
    t = AssetType(type_name=name or f"Amo type {_n()}", category="server")
    db.add(t)
    db.flush()
    return t


def _asset(db, t, **kw):
    kw.setdefault("asset_name", f"amo-{_n()}")
    kw.setdefault("ip_address", f"10.66.{_seq[0] % 250}.1")
    a = Asset(asset_type_id=t.id, **kw)
    db.add(a)
    db.flush()
    return a


def _by_key(rows):
    return {r["key"]: r for r in rows}


def test_totals_quality_and_breakdowns(db):
    admin = _user(db)
    before = A.overview(db, admin, now=NOW)
    fw = _type(db, "Amo Firewall")
    _asset(db, fw, manufacturer="Fortinet", os_name="FortiOS", created_at=NOW - timedelta(days=2))
    _asset(db, fw, manufacturer=" Fortinet ", os_name="FortiOS", created_at=NOW - timedelta(days=20))
    _asset(db, fw, manufacturer="", ip_address=None, created_at=NOW - timedelta(days=200))
    out = A.overview(db, admin, now=NOW)

    assert out["totals"]["total"] - before["totals"]["total"] == 3
    assert out["totals"]["new_7d"] - before["totals"]["new_7d"] == 1
    assert out["totals"]["new_30d"] - before["totals"]["new_30d"] == 2

    q, q0 = _by_key(out["quality"]), _by_key(before["quality"])
    assert q["no_ip"]["count"] - q0["no_ip"]["count"] == 1
    assert q["no_os"]["count"] - q0["no_os"]["count"] == 1
    assert q["no_owner"]["count"] - q0["no_owner"]["count"] == 3
    assert q["no_owner"]["link"] == "/assets/inventory?missing=owner"
    assert "no_zone" in q                                       # an admin reads risk

    t = _by_key(out["by_type"])[fw.id]
    assert t["count"] == 3 and t["link"] == f"/assets/inventory?type={fw.id}"
    vendor = next(r for r in out["by_vendor"] if r["name"] == "Fortinet")
    assert vendor["count"] >= 2 and vendor["link"] == "/assets/inventory?vendor=Fortinet"   # spaces ignored
    assert out["unclassified"]["vendor"] - before["unclassified"]["vendor"] == 1
    assert out["newest"][0]["name"]


def test_other_row_after_the_biggest(db):
    rows = A._rows([(i, f"v{i}", 10 - i) for i in range(10)], lambda k: f"/x?{k}")
    assert len(rows) == A.TOP + 1 and rows[0]["name"] == "v0"
    assert rows[-1]["other"] and rows[-1]["count"] == 2 + 1 and rows[-1]["link"] is None


def test_zone_breakdown_and_unset_zone(db):
    admin = _user(db)
    before = A.overview(db, admin, now=NOW)
    t = _type(db)
    zone = RiskZone(name=f"Amo zone {_n()}", score=40)
    db.add(zone)
    db.flush()
    chosen, defaulted = _asset(db, t), _asset(db, t)
    db.add(AssetRiskProfile(asset_id=chosen.id, criticality_level="medium", criticality_score=50, zone_id=zone.id,
                            zone_is_default=False))
    db.add(AssetRiskProfile(asset_id=defaulted.id, criticality_level="medium", criticality_score=50, zone_id=zone.id,
                            zone_is_default=True))
    db.flush()
    out = A.overview(db, admin, now=NOW)
    assert _by_key(out["by_zone"])[zone.id]["count"] == 2
    unset = _by_key(out["quality"])["no_zone"]["count"] - _by_key(before["quality"])["no_zone"]["count"]
    assert unset == 1                                           # the defaulted one


def test_unknown_devices_need_noc(db):
    db.add(NetworkEndpoint(mac=f"aa:bb:cc:66:00:{_n() % 99:02d}", ip="10.66.9.9", first_seen_at=NOW - timedelta(days=1),
                           last_seen_at=NOW))
    db.flush()
    admin = _user(db)
    out = A.overview(db, admin, now=NOW)["unknown_devices"]
    assert out["open"] >= 1 and out["new_7d"] >= 1 and out["link"] == "/noc/unknown-devices"
    clerk = _user(db, role=UserRole.USER, read=("asset_list",))
    plain = A.overview(db, clerk, now=NOW)
    assert plain["unknown_devices"] is None
    assert "no_zone" not in _by_key(plain["quality"])          # zones belong to risk
    assert [c["key"] for c in plain["coverage"]] == ["eol_known"]


def test_route_needs_asset_list(db):
    from app.core.dependencies import require_permission
    nobody = _user(db, role=UserRole.USER)
    with pytest.raises(HTTPException) as e:
        require_permission("ASSET_LIST", "read")(current_user=nobody, db=db)
    assert e.value.status_code == 403
