"""
The hardening overview (app/modules/dashboard/hardening_overview.py): the success rate and counts of
executed actions (previews left out), failures a later success did not make good, changes not verified
or not holding, assets hardened since their last audit, controls missing in the latest audits, and the
impact in findings and risk.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.hardening import HardeningAction
from app.models.risk import AssetRiskHistory, AssetRiskScore
from app.modules.dashboard import hardening_overview as H

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


@pytest.fixture
def user(db):
    u = User(username=f"hdo_{_n()}", email=f"hdo{_seq[0]}@corp.example", hashed_password="x", role=UserRole.ADMIN,
             is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db):
    t = AssetType(type_name=f"Hdo type {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"hdo-{_seq[0]}", asset_type_id=t.id, ip_address=f"10.44.{_seq[0] % 250}.1")
    db.add(a)
    db.flush()
    return a


def _audit(db, user, asset, when, results):
    s = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address, device_type=DeviceType.LINUX,
                     status="completed", started_at=when, compliance_pct=50)
    db.add(s)
    db.flush()
    rows = []
    for check, sev, st in results:
        r = AuditResult(session_id=s.id, check_number=check, check_title=f"Check {check}", severity=sev, level="L1",
                        status=st)
        db.add(r)
        rows.append(r)
    db.flush()
    return s, rows


def _act(db, user, asset, session, result, status, when, action_type="execute", **kw):
    h = HardeningAction(audit_result_id=result.id, user_id=user.id, asset_id=asset.id, audit_session_id=session.id,
                        check_number=result.check_number, check_title=result.check_title, action_type=action_type,
                        status=status, commands_json=json.dumps(["x"]), created_at=when, executed_at=when, **kw)
    db.add(h)
    db.flush()
    return h


def test_figures_and_failures(db, user):
    before = H.figures(db, NOW)
    a = _asset(db)
    s, (r1, r2) = _audit(db, user, a, NOW - timedelta(days=5), [("9.1.1", "high", CheckStatus.FAIL),
                                                               ("9.1.2", "critical", CheckStatus.FAIL)])
    _act(db, user, a, s, r1, "failed", NOW - timedelta(days=4), error_message="Permission denied")
    _act(db, user, a, s, r1, "success", NOW - timedelta(days=3), verification_passed=True)   # made good
    _act(db, user, a, s, r2, "failed", NOW - timedelta(days=2), output="line\n" * 200 + "% Invalid input")
    _act(db, user, a, s, r2, "success", NOW - timedelta(days=9), action_type="preview")      # not hardening
    after = H.figures(db, NOW)
    assert after["actions_done"] - before["actions_done"] == 3
    assert after["succeeded"] - before["succeeded"] == 1 and after["failed"] - before["failed"] == 2
    assert after["open_failures"] - before["open_failures"] == 1
    assert after["hardened_assets"] - before["hardened_assets"] == 1

    failed = H.attention(db)["failed"]
    mine = [f for f in failed["items"] if f["asset_id"] == a.id]
    assert [f["check_number"] for f in mine] == ["9.1.2"]
    assert mine[0]["error"].endswith("% Invalid input") and mine[0]["error"].startswith("…")
    assert mine[0]["restore_link"] == f"/backup?asset={a.id}" and mine[0]["has_backup"] is False


def test_unverified_and_not_reaudited(db, user):
    a, b = _asset(db), _asset(db)
    s, (r,) = _audit(db, user, a, NOW - timedelta(days=10), [("7.1", "high", CheckStatus.FAIL)])
    _act(db, user, a, s, r, "success", NOW - timedelta(days=5), verification_passed=False)
    sb, (rb,) = _audit(db, user, b, NOW - timedelta(days=10), [("7.2", "high", CheckStatus.FAIL)])
    _act(db, user, b, sb, rb, "success", NOW - timedelta(days=6), verification_passed=True)
    _audit(db, user, b, NOW - timedelta(days=1), [("7.2", "high", CheckStatus.PASS)])          # b audited again
    out = H.attention(db)
    states = {u["asset_id"]: u["state"] for u in out["unverified"]["items"]}
    assert states.get(a.id) == "not_holding" and b.id not in states
    stale = {x["asset_id"] for x in out["not_reaudited"]["items"]}
    assert a.id in stale and b.id not in stale


def test_missing_controls_from_latest_audits(db, user):
    a = _asset(db)
    _audit(db, user, a, NOW - timedelta(days=30), [("5.5.old", "low", CheckStatus.FAIL)])       # superseded
    s, (fixed, left) = _audit(db, user, a, NOW - timedelta(days=2), [("5.5.1", "high", CheckStatus.FAIL),
                                                                   ("5.5.2", "high", CheckStatus.FAIL)])
    _act(db, user, a, s, fixed, "success", NOW - timedelta(days=1))
    checks = {m["check_number"]: m for m in H.missing(db)}
    assert "5.5.2" in checks and "5.5.1" not in checks and "5.5.old" not in checks
    assert checks["5.5.2"]["link"] == "/remediation?q=5.5.2"


def test_impact_in_findings_and_risk(db, user):
    before = H.impact(db, NOW)
    a = _asset(db)
    s, (r,) = _audit(db, user, a, NOW - timedelta(days=20), [("3.3", "critical", CheckStatus.FAIL)])
    db.add(AssetRiskHistory(asset_id=a.id, risk_score=80, risk_level="high", calculated_at=NOW - timedelta(days=15)))
    _act(db, user, a, s, r, "success", NOW - timedelta(days=10))
    db.add(AssetRiskScore(asset_id=a.id, final_risk_score=60, risk_level="medium"))
    db.flush()
    after = H.impact(db, NOW)
    assert after["critical_fixed"] - before["critical_fixed"] == 1
    assert after["risk"]["assets"] - before["risk"]["assets"] == 1
    if before["risk"]["assets"] == 0:
        assert (after["risk"]["before"], after["risk"]["now"]) == (80.0, 60.0)


def test_route(db, user):
    from app.modules.dashboard.overview_router import hardening_overview
    out = hardening_overview(current_user=user, db=db)
    assert set(out) == {"figures", "attention", "missing", "impact", "coverage"}
