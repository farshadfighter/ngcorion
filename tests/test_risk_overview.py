"""
The risk overview (app/modules/dashboard/risk_overview.py): totals per level, the factors' average
contribution and share, the zone-by-level matrix, the trend with critical and high counts taken from each
asset's latest score, and the reasons of incomplete scores with the page that fixes each.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.risk import AssetRiskHistory, AssetRiskScore, RiskZone
from app.modules.dashboard import risk_overview as R

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


def _asset(db, name=None):
    t = AssetType(type_name=f"Rio type {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=name or f"rio-{_seq[0]}", asset_type_id=t.id, ip_address=f"10.55.{_seq[0] % 250}.1")
    db.add(a)
    db.flush()
    return a


def _score(db, asset, score, level, zone=None, **kw):
    s = AssetRiskScore(asset_id=asset.id, final_risk_score=score, risk_level=level,
                       zone_id=zone.id if zone else None, zone_name=zone.name if zone else None, **kw)
    db.add(s)
    db.flush()
    return s


def test_totals_matrix_and_factors(db):
    before = R.totals(db)
    zone = RiskZone(name=f"Rio DMZ {_n()}", score=60)
    db.add(zone)
    db.flush()
    _score(db, _asset(db), 90, "critical", zone, cve_kev_count=1, vulnerability_contribution=40,
           criticality_contribution=20)
    _score(db, _asset(db), 70, "high", zone, audit_contribution=30)
    _score(db, _asset(db), 30, "low", incomplete_data=True, incomplete_reasons_json=["missing_audit", "missing_zone"])
    after = R.totals(db)
    assert after["scored"] - before["scored"] == 3
    assert after["by_level"]["critical"] - before["by_level"]["critical"] == 1
    assert after["incomplete"] - before["incomplete"] == 1 and after["kev_assets"] - before["kev_assets"] == 1

    row = next(r for r in R.matrix(db) if r["zone_id"] == zone.id)
    assert row["counts"]["critical"] == 1 and row["counts"]["high"] == 1 and row["total"] == 2
    assert R.matrix(db)[-1]["zone_id"] is None                  # the asset without a zone, last

    factors = {f["key"]: f for f in R.factors(db)}
    assert [f["key"] for f in R.factors(db)] == [k for k, _ in R.FACTORS]
    assert factors["vulnerability"]["average"] > 0 and sum(f["share"] for f in factors.values()) in (99, 100, 101)


def test_incomplete_reasons_link_to_the_fix(db):
    before = {r["key"]: r["count"] for r in R.incomplete(db)["reasons"]}
    a = _asset(db, "rio-never-audited")
    _score(db, a, 50, "medium", incomplete_data=True, incomplete_reasons_json=["missing_audit", "missing_port_scan"])
    out = R.incomplete(db)
    reasons = {r["key"]: r for r in out["reasons"]}
    assert reasons["missing_audit"]["count"] - before.get("missing_audit", 0) == 1
    assert reasons["missing_audit"]["link"] == "/assets/groups"
    assert reasons["missing_port_scan"]["link"] == "/assets/discovery"
    listed = next(x for x in out["assets"] if x["asset_id"] == a.id)
    assert listed["reasons"] == ["missing_audit", "missing_port_scan"]


def test_trend_counts_levels_from_latest_scores(db):
    a, b = _asset(db), _asset(db)
    for asset, days, score, level in ((a, 40, 85, "critical"), (a, 10, 65, "high"), (b, 35, 70, "high")):
        db.add(AssetRiskHistory(asset_id=asset.id, risk_score=score, risk_level=level,
                                calculated_at=NOW - timedelta(days=days)))
    db.flush()
    points = {p["at"]: p for p in R.trend(db, NOW)}
    now = points[NOW.isoformat() + "Z"]
    assert (now["critical"], now["high"], now["assets"]) == (0, 2, 2)      # a dropped from critical to high
    month = points[(NOW - timedelta(days=30)).isoformat() + "Z"]
    assert (month["critical"], month["high"]) == (1, 1)


def test_route(db):
    from app.modules.dashboard.overview_router import risk_overview
    admin = User(username=f"rio_{_n()}", email=f"rio{_seq[0]}@corp.example", hashed_password="x",
                 role=UserRole.ADMIN, is_active=True)
    db.add(admin)
    db.flush()
    out = risk_overview(current_user=admin, db=db)
    assert set(out) == {"totals", "factors", "matrix", "trend", "incomplete", "top_assets"}
