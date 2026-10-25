"""
The organisation's benchmark policy (app/modules/audit_policy): requesting and deciding rules (four eyes,
who may decide what), rescoring audits under the rules (one check, a whole level, a group's assets),
the module's own score kept and restored, expiry, remediation items closed "by policy", excluded checks
out of the risk score, the checks catalogue, the audit trail and the guarded routes.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.asset_groups import AssetGroup, AssetGroupMember
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.audit_policy import AuditPolicyRule
from app.models.remediation import RemediationItem
from app.models.security_audit_log import AuditLog as SecurityAuditLog
from app.modules.audit_policy import router as R
from app.modules.audit_policy import service as P

P_, F_, NA = CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.NOT_APPLICABLE


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


def _user(db, role=UserRole.ADMIN):
    u = User(username=f"pol_{_n()}", hashed_password="x", role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db):
    t = AssetType(type_name=f"Server {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"pol-{_n()}", asset_type_id=t.id, ip_address=f"10.66.0.{_n() % 250}")
    db.add(a)
    db.flush()
    return a


# check, severity, level, status
RESULTS = [("1.1", "high", "L1", P_), ("1.2", "high", "L1", F_), ("2.1", "medium", "L1", F_),
           ("3.1", "low", "L2", F_), ("3.2", "low", "L2", P_), ("9.9", "info", "INFO", F_)]


def _audit(db, asset, user, results=RESULTS, when=None, raw=(40.0, 50.0), device_type="linux"):
    when = when or datetime.utcnow()
    s = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address, device_type=device_type,
                     status="completed", started_at=when, completed_at=when,
                     compliance_pct=raw[0], weighted_compliance_pct=raw[1])
    db.add(s)
    db.flush()
    for check, sev, level, st in results:
        db.add(AuditResult(session_id=s.id, check_number=check, check_title=f"Check {check}", severity=sev,
                           level=level, status=st))
    db.flush()
    return s


def _req():
    return SimpleNamespace(client=SimpleNamespace(host="10.0.0.9"))


def _ask(db, user, **kw):
    body = {"benchmark": "linux", "decision": "excluded", "reason": "Not used in this organisation", **kw}
    return R.request_rule(R.RuleIn(**body), request=_req(), current_user=user, db=db)


def _decide(db, user, rule_id, approve=True):
    return R.decide(rule_id, R.DecideIn(approve=approve), request=_req(), current_user=user, db=db)


def _results(db, session):
    return {r.check_number: r.policy for r in db.query(AuditResult).filter_by(session_id=session.id)}


# ── the rules ───────────────────────────────────────────────────────────────

def test_no_rule_leaves_the_modules_score(db):
    user = _user(db)
    s = _audit(db, _asset(db), user)
    P.run_pending(db)
    db.refresh(s)
    assert (s.compliance_pct, s.weighted_compliance_pct) == (40.0, 50.0)
    assert s.policy_checked_at is not None and s.raw_compliance_pct is None


def test_excluding_a_check_rescores_and_ending_restores(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    s = _audit(db, _asset(db), requester)
    P.run_pending(db)
    rule = _ask(db, requester, check_number="2.1")
    assert rule.status == "pending" and rule.check_title == "Check 2.1" and rule.severity == "medium"
    with pytest.raises(HTTPException) as own:
        _decide(db, requester, rule.id)
    assert own.value.status_code == 403                                       # never your own request
    out = _decide(db, approver, rule.id)
    assert out.status == "approved" and out.in_force and out.results == 1
    db.refresh(s)
    assert _results(db, s)["2.1"] == "excluded" and _results(db, s)["1.2"] is None
    # passed / (passed + failed) over 1.1 P, 1.2 F, 3.1 F, 3.2 P (2.1 out, info out)
    assert s.compliance_pct == 50.0 and s.raw_compliance_pct == 40.0 and s.policy_excluded == 1
    # weights: high 3 + 3, low 1 + 1 -> passed 3 + 1 of 8
    assert s.weighted_compliance_pct == 50.0 and s.raw_weighted_compliance_pct == 50.0
    R.end_rule(rule.id, request=_req(), current_user=approver, db=db)
    db.refresh(s)
    assert (s.compliance_pct, s.weighted_compliance_pct, s.policy_excluded) == (40.0, 50.0, 0)
    assert _results(db, s)["2.1"] is None


def test_a_whole_level_and_who_may_decide(db):
    requester, manager, admin = _user(db, UserRole.USER), _user(db, UserRole.MANAGER), _user(db)
    s = _audit(db, _asset(db), requester)
    rule = _ask(db, requester, level="l2", decision="optional")
    assert rule.level == "L2" and rule.can_decide            # a user cannot decide
    with pytest.raises(HTTPException) as mgr:
        _decide(db, manager, rule.id)
    assert mgr.value.status_code == 403 and "administrator" in mgr.value.detail
    _decide(db, admin, rule.id)
    db.refresh(s)
    marks = _results(db, s)
    assert marks["3.1"] == marks["3.2"] == "optional" and marks["1.1"] is None
    assert s.compliance_pct == round(100 / 3, 2) and s.policy_optional == 2      # 1.1 P, 1.2 F, 2.1 F


def test_excluding_a_high_check_needs_an_administrator(db):
    requester, manager = _user(db, UserRole.USER), _user(db, UserRole.MANAGER)
    _audit(db, _asset(db), requester)
    rule = _ask(db, requester, check_number="1.2")
    with pytest.raises(HTTPException) as denied:
        _decide(db, manager, rule.id)
    assert denied.value.status_code == 403
    # Making it optional instead is a manager's decision.
    R.end_rule(rule.id, request=_req(), current_user=requester, db=db)              # withdrawn by its requester
    optional = _ask(db, requester, check_number="1.2", decision="optional")
    assert _decide(db, manager, optional.id).status == "approved"


def test_a_group_rule_covers_its_assets_only(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    inside, outside = _asset(db), _asset(db)
    g = AssetGroup(name=f"DMZ {_n()}", kind="static", created_by=approver.id)
    db.add(g)
    db.flush()
    db.add(AssetGroupMember(group_id=g.id, asset_id=inside.id))
    db.flush()
    s_in, s_out = _audit(db, inside, requester), _audit(db, outside, requester)
    rule = _ask(db, requester, check_number="2.1", group_id=g.id)
    _decide(db, approver, rule.id)
    assert _results(db, s_in)["2.1"] == "excluded" and _results(db, s_out)["2.1"] is None
    db.refresh(s_out)
    assert s_out.compliance_pct == 40.0


def test_duplicates_and_bad_requests(db):
    user = _user(db)
    _audit(db, _asset(db), user)
    _ask(db, user, check_number="2.1")
    with pytest.raises(HTTPException) as dup:
        _ask(db, user, check_number="2.1")
    assert dup.value.status_code == 409
    with pytest.raises(HTTPException) as unknown:
        _ask(db, user, check_number="no-such-check")
    assert unknown.value.status_code == 400
    with pytest.raises(ValueError):
        R.RuleIn(benchmark="linux", decision="excluded", reason="long enough reason", check_number="1", level="L2")
    with pytest.raises(ValueError):
        R.RuleIn(benchmark="nope", decision="excluded", reason="long enough reason", check_number="1")


def test_expiry_ends_a_rule(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    s = _audit(db, _asset(db), requester)
    rule = _ask(db, requester, check_number="2.1", expires_at=datetime.utcnow() + timedelta(days=1))
    _decide(db, approver, rule.id)
    db.refresh(s)
    assert s.compliance_pct == 50.0
    P.run_pending(db, now=datetime.utcnow() + timedelta(days=2))
    db.refresh(s)
    assert db.get(AuditPolicyRule, rule.id).status == "expired"
    P.run_pending(db, now=datetime.utcnow() + timedelta(days=2))
    db.refresh(s)
    assert s.compliance_pct == 40.0 and _results(db, s)["2.1"] is None


def test_a_new_audit_is_scored_under_the_policy(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    asset = _asset(db)
    _audit(db, asset, requester, when=datetime.utcnow() - timedelta(days=1))
    rule = _ask(db, requester, check_number="2.1")
    _decide(db, approver, rule.id)
    later = _audit(db, asset, requester)
    assert later.policy_checked_at is None
    P.run_pending(db)
    db.refresh(later)
    assert later.compliance_pct == 50.0 and _results(db, later)["2.1"] == "excluded"


# ── what the policy changes elsewhere ───────────────────────────────────────

def test_remediation_closes_items_by_policy(db):
    from app.modules.remediation import service as rem
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    asset = _asset(db)
    _audit(db, asset, requester)
    rem.sync(db)
    keys = {i.key: i for i in db.query(RemediationItem).filter(RemediationItem.asset_id == asset.id)}
    assert f"audit:{asset.id}:2.1" in keys and f"audit:{asset.id}:3.1" in keys
    _decide(db, approver, _ask(db, requester, check_number="2.1").id)
    _decide(db, approver, _ask(db, requester, level="L2", decision="optional").id)
    rem.sync(db)
    items = {i.key: i for i in db.query(RemediationItem).filter(RemediationItem.asset_id == asset.id)}
    assert items[f"audit:{asset.id}:2.1"].status == "resolved"
    assert items[f"audit:{asset.id}:2.1"].closed_reason == "by_policy"
    assert items[f"audit:{asset.id}:3.1"].closed_reason == "by_policy"
    assert items[f"audit:{asset.id}:1.2"].status == "open"


def test_excluded_checks_leave_the_risk_score_optional_ones_stay(db):
    from app.modules.risk.service import AssetRiskCalculationService
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    asset = _asset(db)
    _audit(db, asset, requester)
    svc = AssetRiskCalculationService()
    settings = svc._load_settings(db)
    before = svc._audit_and_hardening_risk(db, asset.id, settings)
    _decide(db, approver, _ask(db, requester, check_number="2.1").id)
    _decide(db, approver, _ask(db, requester, level="L2", decision="optional").id)
    after = svc._audit_and_hardening_risk(db, asset.id, settings)
    assert after["active_findings"] == before["active_findings"] - 1        # 2.1 gone, 3.1 (optional) stays
    assert after["applicable_weight"] < before["applicable_weight"]


# ── the page's data ────────────────────────────────────────────────────────

def test_checks_benchmarks_and_lists(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    _audit(db, _asset(db), requester)
    checks = R.list_checks(benchmark="linux", q="check 2", current_user=requester, db=db)
    assert [c["check_number"] for c in checks["checks"]] == ["2.1"] and checks["checks"][0]["failed_now"] >= 1
    assert "L2" in R.list_checks(benchmark="linux", q=None, current_user=requester, db=db)["levels"]
    rule = _ask(db, requester, check_number="2.1")
    pending = R.list_rules(status="pending", benchmark="linux", current_user=approver, db=db)
    assert [r.id for r in pending] == [rule.id] and pending[0].can_decide is None and pending[0].can_end
    _decide(db, approver, rule.id)
    bench = R.list_benchmarks(current_user=approver, db=db)
    linux = next(b for b in bench["benchmarks"] if b["benchmark"] == "linux")
    assert linux["excluded"] >= 1 and linux["raw_score"] is not None and bench["in_force"] >= 1
    assert [r.id for r in R.list_rules(status="in_force", benchmark="linux", current_user=approver, db=db)] == [rule.id]


def test_audit_trail_sentences(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    _audit(db, _asset(db), requester)
    rule = _ask(db, requester, check_number="2.1")
    _decide(db, approver, rule.id)
    R.end_rule(rule.id, request=_req(), current_user=approver, db=db)
    details = [d for (d,) in db.query(SecurityAuditLog.detail).filter(SecurityAuditLog.target_id == rule.id,
                                                                      SecurityAuditLog.module == "auditing")]
    assert "Asked to exclude 2.1 of the linux benchmark" in details
    assert "Approved excluding 2.1 of the linux benchmark" in details
    assert "Ended the rule excluding 2.1 of the linux benchmark" in details


def test_routes_are_guarded():
    assert len(R.router.routes) >= 6
    for route in R.router.routes:
        deps = [d.call for d in route.dependant.dependencies]
        assert any(getattr(c, "permission", None) for c in deps), route.path


# ── every family, audited or not (app/modules/audit_policy/catalog.py) ─────────

def test_every_family_has_its_catalog():
    from app.models.audit import DeviceType
    from app.modules.audit_policy import catalog
    for dt in DeviceType:
        rows = catalog.checks(dt.value)
        assert rows, dt.value
        numbers = [c["check_number"] for c in rows]
        assert len(numbers) == len(set(numbers)), dt.value
        assert all(c["level"] in (None, "L1", "L2", "INFO") for c in rows), dt.value
        assert all(c["severity"] in (None, "critical", "high", "medium", "low", "info") for c in rows), dt.value
    # the numbers the audits write
    assert catalog.find("fortinet", "FG-BL-043") and catalog.find("windows", "WIN-2025-1.1.1")
    assert catalog.find("cisco", "CIS-1.1.1") and catalog.find("cisco", "IOS-L1-0010")
    assert catalog.find("docker", "DKR-1.1.1") and catalog.find("linux", "LNX-L1-1.1.1.1")


def test_a_family_never_audited_gets_its_rules(db):
    requester, approver = _user(db, UserRole.MANAGER), _user(db)
    bench = R.list_benchmarks(current_user=requester, db=db)["benchmarks"]
    from app.models.audit import DeviceType
    assert {b["benchmark"] for b in bench} == {d.value for d in DeviceType}
    assert all(b["checks"] > 0 for b in bench)

    checks = R.list_checks(benchmark="docker", q="DKR-1.1.1", current_user=requester, db=db)
    assert checks["checks"][0]["check_number"] == "DKR-1.1.1" and checks["checks"][0]["failed_now"] == 0
    assert "L1" in R.list_checks(benchmark="docker", q=None, current_user=requester, db=db)["levels"]

    # the title and severity come from the catalog; approved, a later audit is scored under it
    rule = _ask(db, requester, benchmark="docker", check_number="DKR-1.1.1", decision="optional")
    assert rule.check_title and rule.severity == "medium"
    _decide(db, approver, rule.id)
    s = _audit(db, _asset(db), requester, device_type="docker",
               results=[("DKR-1.1.1", "medium", "L1", F_), ("DKR-1.1.2", "medium", "L1", F_)])
    from app.modules.audit_policy import service
    service.run_pending(db, limit=None)
    assert _results(db, s)["DKR-1.1.1"] == "optional" and _results(db, s)["DKR-1.1.2"] is None

    # what fails counts only this family's audits
    assert R.list_checks(benchmark="docker", q="DKR-1.1.2", current_user=requester, db=db)["checks"][0]["failed_now"] == 1
    with pytest.raises(HTTPException) as unknown:
        _ask(db, requester, benchmark="sophos", check_number="DKR-1.1.1")
    assert unknown.value.status_code == 400
