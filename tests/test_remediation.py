"""
Remediation tracking and risk acceptance: the sync (create, resolve, reopen,
hardening, architecture decisions, CVE with KEV deadlines), manual changes,
risk acceptance (who may decide, limits, scope, expiry) and its effect on the
risk score, the API views and the three alert evaluators.

Everything runs inside a rolled-back transaction; sync() looks at the whole
database, so assertions only look at this test's assets.
"""
import importlib
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, User, UserRole
from app.models.architecture_finding import ArchitectureFinding
from app.models.asset_owners import AssetOwner
from app.models.asset_types import AssetType
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.cve import AssetSoftware
from app.models.hardening import HardeningAction
from app.models.remediation import RemediationEvent, RemediationItem, RiskAcceptance
from app.modules.alerts import events as alert_events
from app.modules.cve import feeds, store
from app.modules.cve import settings as cve_settings
from app.modules.remediation import service
from app.modules.remediation.service import RemediationError
from app.modules.risk.seed import seed_risk_defaults
from app.modules.risk.service import AssetRiskCalculationService

sys.path.insert(0, str(Path(__file__).parent))
from test_cve import _match, _nvd_cve, nvd_page  # noqa: E402

api = importlib.import_module("app.modules.remediation.router")


@pytest.fixture
def db():
    connection = db_engine.connect()
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


def _user(db, role=UserRole.ADMIN, email=None):
    n = _n()
    u = User(username=f"rem_user_{n}", email=email or f"rem{n}@example.com", hashed_password="x", role=role,
             is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db, owner_email=None, **kw):
    t = AssetType(type_name=f"Server {_n()}", category="server")
    db.add(t)
    db.flush()
    owner_id = None
    if owner_email:
        creator = _user(db)
        o = AssetOwner(full_name=f"Owner {_n()}", email=owner_email, user_id=creator.id)
        db.add(o)
        db.flush()
        owner_id = o.id
    a = Asset(asset_name=f"rem-asset-{_n()}", asset_type_id=t.id, ip_address=f"10.77.{_n() % 250}.{_n() % 250}",
              owner_id=owner_id, **kw)
    db.add(a)
    db.flush()
    return a


def _audit(db, asset, results, when, status="completed", user=None):
    """results: [(check_number, severity, CheckStatus, vdom)]"""
    user = user or _user(db)
    s = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address or "10.0.0.1",
                     device_type="linux", status=status, started_at=when, completed_at=when)
    db.add(s)
    db.flush()
    rows = []
    for check, sev, st, vdom in results:
        r = AuditResult(session_id=s.id, check_number=check, check_title=f"Check {check}", severity=sev,
                        status=st, vdom=vdom)
        db.add(r)
        rows.append(r)
    db.flush()
    return s, rows


def _items(db, asset):
    return {i.key: i for i in db.query(RemediationItem).filter(RemediationItem.asset_id == asset.id)}


FAIL, PASS = CheckStatus.FAIL, CheckStatus.PASS


# ── sync: audit ─────────────────────────────────────────────────────────────

def test_failed_checks_become_items_with_sla_deadline_and_owner(db):
    owner = _user(db, UserRole.USER, email="Owner.Person@Example.com")
    asset = _asset(db, owner_email="owner.person@example.com")
    _audit(db, asset, [("5.2.7", "critical", FAIL, None), ("1.1.1", "low", FAIL, None),
                       ("4.1.1", "medium", PASS, None)], datetime(2026, 9, 1))
    now = datetime(2026, 9, 2, 8, 0)
    stats = service.sync(db, now=now)
    items = _items(db, asset)
    assert stats["created"] >= 2
    crit = items[f"audit:{asset.id}:5.2.7"]
    low = items[f"audit:{asset.id}:1.1.1"]
    assert f"audit:{asset.id}:4.1.1" not in items
    assert crit.status == "open" and crit.severity == "critical"
    assert crit.due_at == now + timedelta(days=15)
    assert low.due_at == now + timedelta(days=180)
    assert crit.owner_id == owner.id
    kinds = [e.kind for e in db.query(RemediationEvent).filter(RemediationEvent.item_id == crit.id)]
    assert kinds == ["created", "assigned"]


def test_item_resolves_when_next_audit_passes_and_reopens_when_it_fails_again(db):
    asset = _asset(db)
    _audit(db, asset, [("5.2.7", "high", FAIL, None), ("2.2.2", "medium", FAIL, None)], datetime(2026, 9, 1))
    service.sync(db, now=datetime(2026, 9, 1, 12))
    _audit(db, asset, [("5.2.7", "high", PASS, None), ("2.2.2", "medium", FAIL, None)], datetime(2026, 9, 10))
    service.sync(db, now=datetime(2026, 9, 10, 12))
    items = _items(db, asset)
    fixed = items[f"audit:{asset.id}:5.2.7"]
    assert fixed.status == "resolved" and fixed.closed_reason == "fixed"
    assert fixed.resolved_at == datetime(2026, 9, 10, 12)
    assert items[f"audit:{asset.id}:2.2.2"].status == "open"

    _audit(db, asset, [("5.2.7", "high", FAIL, None)], datetime(2026, 9, 20))
    service.sync(db, now=datetime(2026, 9, 20, 12))
    db.refresh(fixed)
    assert fixed.status == "open" and fixed.reopened == 1 and fixed.resolved_at is None
    assert fixed.due_at == datetime(2026, 9, 20, 12) + timedelta(days=30)


def test_failed_connection_audit_does_not_resolve_items(db):
    asset = _asset(db)
    _audit(db, asset, [("5.2.7", "high", FAIL, None)], datetime(2026, 9, 1))
    service.sync(db, now=datetime(2026, 9, 1, 12))
    _audit(db, asset, [], datetime(2026, 9, 5), status="failed")
    service.sync(db, now=datetime(2026, 9, 5, 12))
    assert _items(db, asset)[f"audit:{asset.id}:5.2.7"].status == "open"


def test_vdom_checks_are_separate_items(db):
    asset = _asset(db)
    _audit(db, asset, [("FG-POL-001", "medium", FAIL, "root"), ("FG-POL-001", "medium", FAIL, "dmz"),
                       ("FG-BL-010", "low", FAIL, "global")], datetime(2026, 9, 1))
    service.sync(db, now=datetime(2026, 9, 1, 12))
    keys = set(_items(db, asset))
    assert {f"audit:{asset.id}:FG-POL-001:root", f"audit:{asset.id}:FG-POL-001:dmz",
            f"audit:{asset.id}:FG-BL-010"} <= keys


def test_successful_hardening_moves_item_to_pending_verification(db):
    asset = _asset(db)
    user = _user(db)
    session, rows = _audit(db, asset, [("5.2.7", "high", FAIL, None)], datetime(2026, 9, 1), user=user)
    service.sync(db, now=datetime(2026, 9, 1, 12))
    db.add(HardeningAction(audit_result_id=rows[0].id, user_id=user.id, asset_id=asset.id,
                           audit_session_id=session.id, check_number="5.2.7", check_title="x",
                           action_type="execute", status="success", commands_json=[]))
    db.flush()
    service.sync(db, now=datetime(2026, 9, 2))
    item = _items(db, asset)[f"audit:{asset.id}:5.2.7"]
    assert item.status == "pending_verification"


def test_deleted_asset_closes_its_items(db):
    asset = _asset(db)
    _audit(db, asset, [("5.2.7", "high", FAIL, None)], datetime(2026, 9, 1))
    service.sync(db, now=datetime(2026, 9, 1, 12))
    item = _items(db, asset)[f"audit:{asset.id}:5.2.7"]
    for s in db.query(AuditSession).filter(AuditSession.asset_id == asset.id):
        db.query(AuditResult).filter(AuditResult.session_id == s.id).delete()
        db.delete(s)
    db.flush()
    db.delete(asset)
    db.flush()
    service.sync(db, now=datetime(2026, 9, 2))
    db.refresh(item)
    assert item.status == "resolved" and item.closed_reason == "asset_deleted"


# ── sync: architecture and CVE ──────────────────────────────────────────────

def test_architecture_findings_follow_their_page_decision(db):
    asset = _asset(db)
    f = ArchitectureFinding(rule_code="AV-012", title="Critical asset lacks redundancy", severity="high",
                            category="topology", asset_id=asset.id, asset_name=asset.asset_name, status="open")
    db.add(f)
    db.flush()
    service.sync(db, now=datetime(2026, 9, 1))
    item = _items(db, asset)[f"arch:{asset.id}:AV-012"]
    assert item.status == "open" and item.severity == "high"
    f.status = "ignored"
    db.flush()
    service.sync(db, now=datetime(2026, 9, 2))
    db.refresh(item)
    assert item.status == "accepted" and item.acceptance_id is None
    db.delete(f)
    db.flush()
    service.sync(db, now=datetime(2026, 9, 3))
    db.refresh(item)
    assert item.status == "resolved"


def _load_cve(db, asset):
    db.add(AssetSoftware(asset_id=asset.id, vendor="apache", product="http_server", version="2.4.49"))
    db.flush()
    store.apply_cves(db, feeds.parse_nvd_page(nvd_page(
        _nvd_cve("CVE-2021-41773", score=7.5, severity="HIGH",
                 matches=[_match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")]),
        _nvd_cve("CVE-2021-42013", score=9.8, severity="CRITICAL",
                 matches=[_match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")]))))
    store.apply_kev(db, feeds.parse_kev({"catalogVersion": "1", "dateReleased": "2026-09-30T00:00:00.000Z",
                                         "vulnerabilities": [{"cveID": "CVE-2021-41773", "dateAdded": "2024-01-01",
                                                              "dueDate": "2024-01-15", "requiredAction": "x"}]}))
    cve_settings.put(db, cve_settings.WATERMARK, datetime(2026, 9, 30).isoformat())
    db.flush()


def test_cve_findings_kev_deadline_and_untouched_without_database(db):
    asset = _asset(db)
    _load_cve(db, asset)
    now = datetime(2026, 10, 1)
    service.sync(db, now=now)
    items = _items(db, asset)
    kev = items[f"cve:{asset.id}:CVE-2021-41773"]
    crit = items[f"cve:{asset.id}:CVE-2021-42013"]
    assert kev.kev is True and kev.due_at == now + timedelta(days=7)
    assert crit.severity == "critical" and crit.due_at == now + timedelta(days=15)
    assert kev.detail["installed"] == "2.4.49"

    cve_settings.put(db, cve_settings.WATERMARK, None)
    db.flush()
    service.sync(db, now=now + timedelta(days=1))
    db.refresh(kev)
    assert kev.status == "open"


# ── manual changes ──────────────────────────────────────────────────────────

def _one_item(db, sev="high"):
    asset = _asset(db)
    _audit(db, asset, [("9.9.9", sev, FAIL, None)], datetime(2026, 9, 1))
    service.sync(db, now=datetime(2026, 9, 1, 12))
    return asset, _items(db, asset)[f"audit:{asset.id}:9.9.9"]


def test_update_item_owner_deadline_status_and_note(db):
    user = _user(db)
    owner = _user(db, UserRole.USER)
    _, item = _one_item(db)
    out = api.update_item(item.id, api.ItemUpdate(owner_id=owner.id, due_date="2026-12-31",
                                                  status="in_progress", note="Planned for CR-1"), user, db)
    assert out["owner"] == owner.username and out["status"] == "in_progress"
    assert out["due_at"].startswith("2026-12-31") and out["due_custom"] is True
    assert [e["kind"] for e in out["events"]][-4:] == ["assigned", "due_changed", "status", "note"]

    out = api.update_item(item.id, api.ItemUpdate(due_date=None), user, db)
    assert out["due_custom"] is False and out["due_at"].startswith("2026-10-01")


def test_resolved_items_cannot_be_changed_by_hand(db):
    user = _user(db)
    asset, item = _one_item(db)
    _audit(db, asset, [("9.9.9", "high", PASS, None)], datetime(2026, 9, 5))
    service.sync(db, now=datetime(2026, 9, 5, 12))
    with pytest.raises(HTTPException) as e:
        api.update_item(item.id, api.ItemUpdate(status="open"), user, db)
    assert e.value.status_code == 400


# ── risk acceptance ─────────────────────────────────────────────────────────

def test_acceptance_rules_on_who_decides(db):
    admin, manager, other_manager = _user(db), _user(db, UserRole.MANAGER), _user(db, UserRole.MANAGER)
    plain = _user(db, UserRole.USER)
    _, item = _one_item(db, sev="high")
    acc = service.request_acceptance(db, item, manager, scope="item", justification="Reboot window in Q4",
                                     compensating_control="Module disabled",
                                     expires_at=datetime.utcnow() + timedelta(days=60))
    assert acc.status == "pending"
    with pytest.raises(RemediationError) as e:
        service.decide_acceptance(db, acc, manager, True)
    assert e.value.status_code == 403            # own request
    with pytest.raises(RemediationError):
        service.decide_acceptance(db, acc, plain, True)
    service.decide_acceptance(db, acc, other_manager, True)
    assert acc.status == "approved"
    db.refresh(item)
    assert item.status == "accepted" and item.acceptance_id == acc.id
    assert admin  # an admin could have decided too


def test_critical_needs_an_administrator_and_limits_apply(db):
    manager, admin = _user(db, UserRole.MANAGER), _user(db)
    requester = _user(db, UserRole.MANAGER)
    _, item = _one_item(db, sev="critical")
    with pytest.raises(RemediationError) as e:
        service.request_acceptance(db, item, requester, scope="item", justification="too long a window",
                                   compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=45))
    assert "30 days" in e.value.message
    acc = service.request_acceptance(db, item, requester, scope="item", justification="short window",
                                     compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=20))
    with pytest.raises(RemediationError):
        service.request_acceptance(db, item, requester, scope="item", justification="duplicate one",
                                   compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=10))
    with pytest.raises(RemediationError) as e:
        service.decide_acceptance(db, acc, manager, True)
    assert "administrator" in e.value.message
    service.decide_acceptance(db, acc, admin, True)
    assert acc.status == "approved"


def test_acceptance_expires_and_item_reopens(db):
    requester, admin = _user(db, UserRole.MANAGER), _user(db)
    _, item = _one_item(db, sev="medium")
    acc = service.request_acceptance(db, item, requester, scope="item", justification="Vendor fix pending",
                                     compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=10))
    service.decide_acceptance(db, acc, admin, True)
    service.sync(db, now=datetime.utcnow() + timedelta(days=11))
    db.refresh(acc)
    db.refresh(item)
    assert acc.status == "expired"
    assert item.status == "open" and item.acceptance_id is None
    assert "acceptance_ended" in [e.kind for e in db.query(RemediationEvent).filter(RemediationEvent.item_id == item.id)]


def test_withdrawing_an_active_acceptance_reopens(db):
    requester, admin = _user(db, UserRole.USER), _user(db)
    _, item = _one_item(db, sev="low")
    acc = service.request_acceptance(db, item, requester, scope="item", justification="Legacy system",
                                     compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=30))
    service.decide_acceptance(db, acc, admin, True)
    service.end_acceptance(db, acc, requester)
    db.refresh(item)
    assert acc.status == "revoked" and item.status == "open"


def test_pending_request_is_cancelled_by_its_requester_only(db):
    requester, admin = _user(db, UserRole.USER), _user(db)
    _, item = _one_item(db, sev="low")
    acc = service.request_acceptance(db, item, requester, scope="item", justification="Legacy system",
                                     compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=30))
    assert service.can_withdraw(admin, acc) is False
    with pytest.raises(RemediationError) as e:
        service.end_acceptance(db, acc, admin)        # an admin rejects instead, with a reason
    assert e.value.status_code == 403
    assert service.can_withdraw(requester, acc) is True
    service.end_acceptance(db, acc, requester)
    assert acc.status == "revoked"


def test_ref_scope_covers_every_asset_with_that_check(db):
    requester, admin = _user(db, UserRole.MANAGER), _user(db)
    a1, a2 = _asset(db), _asset(db)
    _audit(db, a1, [("7.7.7", "medium", FAIL, None)], datetime(2026, 9, 1))
    _audit(db, a2, [("7.7.7", "medium", FAIL, None)], datetime(2026, 9, 1))
    service.sync(db, now=datetime(2026, 9, 1, 12))
    item = _items(db, a1)[f"audit:{a1.id}:7.7.7"]
    acc = service.request_acceptance(db, item, requester, scope="ref", justification="Banner not approved",
                                     compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=90))
    service.decide_acceptance(db, acc, admin, True)
    assert _items(db, a1)[f"audit:{a1.id}:7.7.7"].status == "accepted"
    assert _items(db, a2)[f"audit:{a2.id}:7.7.7"].status == "accepted"


def test_accepted_findings_leave_the_risk_score(db):
    seed_risk_defaults(db)
    requester, admin = _user(db, UserRole.MANAGER), _user(db)
    asset = _asset(db)
    _audit(db, asset, [("1.1", "high", FAIL, None), ("1.2", "high", PASS, None)], datetime.utcnow())
    service.sync(db)
    calc = AssetRiskCalculationService()
    settings = calc._load_settings(db) if hasattr(calc, "_load_settings") else None
    before = calc._audit_and_hardening_risk(db, asset.id, settings or calc.get_settings(db))
    assert before["failed_weight"] > 0
    item = _items(db, asset)[f"audit:{asset.id}:1.1"]
    acc = service.request_acceptance(db, item, requester, scope="item", justification="Accepted for test",
                                     compensating_control=None, expires_at=datetime.utcnow() + timedelta(days=30))
    service.decide_acceptance(db, acc, admin, True)
    after = calc._audit_and_hardening_risk(db, asset.id, settings or calc.get_settings(db))
    assert after["failed_weight"] == 0 and after["accepted_findings"] == 1


def test_accepted_cve_leaves_vulnerability_score(db):
    requester, admin = _user(db, UserRole.MANAGER), _user(db)
    asset = _asset(db)
    _load_cve(db, asset)
    service.sync(db)
    calc = AssetRiskCalculationService()
    assert calc._vulnerability_score(db, asset.id)["findings"] == 2
    item = _items(db, asset)[f"cve:{asset.id}:CVE-2021-42013"]
    acc = service.request_acceptance(db, item, requester, scope="item", justification="WAF rule in place",
                                     compensating_control="WAF", expires_at=datetime.utcnow() + timedelta(days=20))
    service.decide_acceptance(db, acc, admin, True)
    assert calc._vulnerability_score(db, asset.id)["findings"] == 1


# ── API views ───────────────────────────────────────────────────────────────

def test_list_views_and_summary(db):
    me = _user(db)
    a = _asset(db)
    _audit(db, a, [("1", "critical", FAIL, None), ("2", "low", FAIL, None)], datetime(2020, 1, 1))
    service.sync(db, now=datetime(2020, 1, 1))     # deadlines long past
    item = _items(db, a)[f"audit:{a.id}:2"]
    api.update_item(item.id, api.ItemUpdate(owner_id=me.id), me, db)
    overdue = api.list_items(view="overdue", source=None, severity=None, asset_id=a.id, q=None, offset=0,
                             limit=50, user=me, db=db)
    assert overdue["total"] == 2 and all(i["overdue"] for i in overdue["items"])
    assert overdue["items"][0]["severity"] == "critical"
    mine = api.list_items(view="mine", source=None, severity=None, asset_id=a.id, q=None, offset=0, limit=50,
                          user=me, db=db)
    assert [i["ref"] for i in mine["items"]] == ["2"]
    found = api.list_items(view="all", source="audit", severity=None, asset_id=None, q=a.asset_name, offset=0,
                           limit=50, user=me, db=db)
    assert found["total"] == 2
    s = api.get_summary(me, db)
    assert s["overdue"] >= 2 and s["open"] >= 2


def test_settings_change_the_deadline_for_new_items(db):
    admin = _user(db)
    api.put_settings(api.RemediationSettings(sla={"kev": 3, "critical": 5, "high": 10, "medium": 20, "low": 40},
                                             accept_max={"kev": 10, "critical": 10, "high": 30, "medium": 60,
                                                          "low": 90}), admin, db)
    asset = _asset(db)
    _audit(db, asset, [("3.3", "high", FAIL, None)], datetime(2026, 9, 1))
    now = datetime(2026, 9, 1, 12)
    service.sync(db, now=now)
    assert _items(db, asset)[f"audit:{asset.id}:3.3"].due_at == now + timedelta(days=10)


def test_acceptance_list_marks_who_may_decide(db):
    requester, admin = _user(db, UserRole.MANAGER), _user(db)
    _, item = _one_item(db, sev="high")
    api.request_acceptance(item.id, api.AcceptanceRequest(scope="item", justification="Reason long enough",
                                                          expires_on=(datetime.utcnow() + timedelta(days=30)).date()),
                           requester, db)
    mine = api.list_acceptances(view="pending", user=requester, db=db)
    theirs = api.list_acceptances(view="pending", user=admin, db=db)
    row = next(r for r in mine["items"] if r["item_id"] == item.id)
    assert row["can_decide"] is False and row["decide_blocked"] == "You cannot decide on your own request"
    assert next(r for r in theirs["items"] if r["item_id"] == item.id)["can_decide"] is True
    # Approving needs no body: the note is optional.
    assert api.approve(row["id"], user=admin, db=db)["status"] == "approved"


# ── alerts ──────────────────────────────────────────────────────────────────

def test_alert_evaluators(db):
    owner, requester, admin = _user(db), _user(db, UserRole.MANAGER), _user(db)
    asset = _asset(db)
    _audit(db, asset, [("8.1", "critical", FAIL, None), ("8.2", "medium", FAIL, None)], datetime(2020, 1, 1))
    service.sync(db, now=datetime(2020, 1, 1))
    items = _items(db, asset)
    overdue_item = items[f"audit:{asset.id}:8.1"]
    overdue_item.owner_id = owner.id
    db.flush()
    now = datetime.utcnow()
    problems = alert_events._remediation_overdue(db, {"days": 0}, now, now)
    mine = [p for p in problems if p.key == f"item:{overdue_item.id}"]
    assert mine and mine[0].owner_user_id == owner.id and mine[0].detail.startswith("8.1 - due ")

    pending = service.request_acceptance(db, items[f"audit:{asset.id}:8.2"], requester, scope="item",
                                         justification="Waiting on vendor", compensating_control=None,
                                         expires_at=now + timedelta(days=5))
    assert any(p.key == f"acceptance:{pending.id}" for p in alert_events._acceptance_pending(db, {}, now, now))
    service.decide_acceptance(db, pending, admin, True)
    expiring = alert_events._acceptance_expiring(db, {"days": 7}, now, now)
    hit = [p for p in expiring if p.key == f"acceptance:{pending.id}"]
    assert hit and hit[0].owner_user_id == requester.id
    assert "remediation.overdue" in alert_events.EVENTS
