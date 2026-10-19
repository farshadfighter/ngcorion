"""
The main dashboard (app/modules/dashboard/overview.py): each "needs action" count and its page, that a
user sees only the parts of the modules they may read, the coverage figures, the 90-day trends taken
from each asset's latest value at every point, and the riskiest assets with their main factor.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserPermission, UserRole
from app.models.audit import AuditSession, DeviceType
from app.models.audit_policy import AuditPolicyRule
from app.models.backup import DeviceBackup
from app.models.noc import AssetSnmpCredential, AssetSnmpStatus
from app.models.notification import Alert
from app.models.remediation import RemediationItem, RiskAcceptance
from app.models.risk import AssetRiskHistory, AssetRiskScore
from app.models.scheduling import ScheduledJob
from app.models.system_backup import SystemBackup
from app.modules.dashboard import overview as S

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
    u = User(username=f"dash_{_n()}", email=f"dash{_seq[0]}@corp.example", hashed_password="x", role=role,
             is_active=True)
    db.add(u)
    db.flush()
    for module in read:
        db.add(UserPermission(user_id=u.id, module=module.upper(), can_read=True))
    db.flush()
    return u


def _asset(db, name=None):
    t = AssetType(type_name=f"Dash type {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=name or f"dash-asset-{_seq[0]}", asset_type_id=t.id, ip_address=f"10.88.{_n() % 250}.1")
    db.add(a)
    db.flush()
    return a


def _counts(db, user):
    return {i["key"]: i["count"] for i in S.attention(db, user, NOW)}


def _seed_attention(db, other):
    a = _asset(db)
    db.add(AssetRiskScore(asset_id=a.id, final_risk_score=70, risk_level="high", cve_kev_count=2))
    db.add(Alert(event_type="cve.kev_finding", module="cve", severity="critical", fingerprint=f"dash:{_n()}",
                 title="KEV on dash asset", status="active"))
    db.add(Alert(event_type="cve.kev_finding", module="cve", severity="critical", fingerprint=f"dash:{_n()}",
                 title="Acknowledged one", status="acknowledged"))
    db.add(RemediationItem(key=f"dash:{_n()}", source="cve", ref="CVE-2099-1", asset_id=a.id, title="Late fix",
                           severity="high", status="open", first_seen_at=NOW - timedelta(days=40),
                           last_seen_at=NOW, due_at=NOW - timedelta(days=1), updated_at=NOW))
    db.add(AssetSnmpCredential(asset_id=a.id, version="v2c", port=161, community_encrypted="x"))
    db.add(AssetSnmpStatus(asset_id=a.id, reachable=False, consecutive_poll_failures=3))
    db.add(DeviceBackup(asset_id=a.id, config_content="hostname x", source="scheduled", change_origin="external",
                        changed=True, created_at=NOW - timedelta(days=2)))
    db.add(DeviceBackup(asset_id=a.id, config_content="hostname y", source="scheduled", change_origin="external",
                        changed=True, created_at=NOW - timedelta(days=20)))
    db.add(ScheduledJob(job_name="Nightly CIS", job_type="audit", technology="linux", asset_id=a.id,
                        params_encrypted="x", recurrence="daily", hour=2, minute=0, enabled=True,
                        next_run_at=NOW + timedelta(hours=10), last_run_status="failed"))
    db.add(RiskAcceptance(source="cve", ref="CVE-2099-1", asset_id=a.id, title="Accept it", severity="high",
                          justification="Isolated", expires_at=NOW + timedelta(days=90), status="pending",
                          requested_by=other.id))
    db.add(AuditPolicyRule(benchmark="linux", check_number="1.1.1", decision="optional", reason="Not used here",
                           status="pending", requested_by=other.id))
    db.add(SystemBackup(kind="scheduled", status="failed", contents=["essential"], destinations=[],
                        created_at=NOW - timedelta(hours=3), filename=f"dash-{_n()}.ngbak"))
    db.flush()
    return a


def test_attention_counts_and_links(db):
    requester = _user(db, role=UserRole.USER)
    admin = _user(db)
    before = _counts(db, admin)
    _seed_attention(db, requester)
    after = _counts(db, admin)
    delta = {k: after.get(k, 0) - before.get(k, 0) for k in after}
    assert delta["kev_assets"] == 1
    assert delta["critical_alerts"] == 1                       # the acknowledged one is not counted
    assert delta["overdue_remediation"] == 1
    assert delta["devices_down"] == 1
    assert delta["external_changes"] == 1                      # one asset, only the change of this week
    assert delta["failed_jobs_audit"] == 1
    assert delta["acceptances_pending"] == 1 and delta["policy_pending"] == 1
    assert after["system_backup_failed"] == 1

    links = {i["key"]: i["link"] for i in S.attention(db, admin, NOW)}
    assert links["critical_alerts"] == "/alerts?severity=critical"
    assert links["overdue_remediation"] == "/remediation?view=overdue"
    assert links["failed_jobs_audit"] == "/audit/schedule-auditing"
    assert all(i["count"] > 0 for i in S.attention(db, admin, NOW))


def test_own_requests_are_not_waiting_for_me(db):
    admin = _user(db)
    before = _counts(db, admin)
    _seed_attention(db, admin)                                  # requested by the admin themself
    after = _counts(db, admin)
    assert after.get("acceptances_pending", 0) == before.get("acceptances_pending", 0)
    assert after.get("policy_pending", 0) == before.get("policy_pending", 0)


def test_only_the_modules_the_user_may_read(db):
    requester = _user(db, role=UserRole.USER)
    _seed_attention(db, requester)
    fixer = _user(db, role=UserRole.MANAGER, read=("remediation",))
    keys = set(_counts(db, fixer))
    # remediation only: overdue items and acceptances to approve, nothing from cve, noc, backup or audit
    assert keys <= {"overdue_remediation", "acceptances_pending"} and "overdue_remediation" in keys
    out = S.overview(db, fixer, now=NOW)
    assert out["assets"] is None and out["coverage"] == [] and out["trend"] == {} and out["top_assets"] is None

    plain = _user(db, role=UserRole.USER, read=("remediation", "cve"))
    keys = set(_counts(db, plain))
    assert "acceptances_pending" not in keys                    # only managers and admins approve
    assert {"kev_assets", "critical_alerts"} <= keys            # cve alerts follow the cve permission
    assert "system_backup_failed" not in keys                   # NGCorion's own backups: admins only


def test_coverage(db):
    admin = _user(db)
    base = {c["key"]: c for c in S.coverage(db, admin, NOW, 0)}
    a, b = _asset(db), _asset(db)
    db.add(AuditSession(user_id=admin.id, asset_id=a.id, target_ip=a.ip_address, device_type=DeviceType.LINUX,
                        status="completed", started_at=NOW - timedelta(days=10), compliance_pct=80))
    db.add(AuditSession(user_id=admin.id, asset_id=b.id, target_ip=b.ip_address, device_type=DeviceType.LINUX,
                        status="completed", started_at=NOW - timedelta(days=200), compliance_pct=60))
    db.add(AssetSnmpCredential(asset_id=b.id, version="v2c", port=161, community_encrypted="x"))
    db.flush()
    got = {c["key"]: c for c in S.coverage(db, admin, NOW, 2)}
    assert got["audited"]["covered"] - base["audited"]["covered"] == 1     # the 200-day-old audit is too old
    assert got["monitored"]["covered"] - base["monitored"]["covered"] == 1
    assert got["audited"]["total"] == 2 and got["audited"]["link"] == "/audit/sessions"
    assert {"backed_up"} <= set(got)


def test_trend_uses_each_assets_latest_value(db):
    admin = _user(db)
    a, b = _asset(db), _asset(db)
    for asset, days, score in ((a, 60, 80), (a, 10, 40), (b, 20, 60)):
        db.add(AssetRiskHistory(asset_id=asset.id, risk_score=score, risk_level="high",
                                calculated_at=NOW - timedelta(days=days)))
    # asset a audited three times in a week: it still counts once
    for days, pct in ((12, 50), (11, 50), (10, 70)):
        db.add(AuditSession(user_id=admin.id, asset_id=a.id, target_ip=a.ip_address, device_type=DeviceType.LINUX,
                            status="completed", started_at=NOW - timedelta(days=days), compliance_pct=pct))
    db.add(AuditSession(user_id=admin.id, asset_id=b.id, target_ip=b.ip_address, device_type=DeviceType.LINUX,
                        status="completed", started_at=NOW - timedelta(days=40), compliance_pct=90))
    db.add(AuditSession(user_id=admin.id, asset_id=b.id, target_ip=b.ip_address, device_type=DeviceType.LINUX,
                        status="running", started_at=NOW - timedelta(days=1), compliance_pct=10))
    db.flush()
    out = S.trend(db, admin, NOW)

    risk = out["risk"]
    assert risk["points"][-1] == {"at": NOW.isoformat() + "Z", "value": 50.0, "assets": 2}
    at = {p["at"]: p for p in risk["points"]}
    assert at[(NOW - timedelta(days=30)).isoformat() + "Z"]["value"] == 80.0   # only a, at 80
    assert (NOW - timedelta(days=65)).isoformat() + "Z" not in at              # before any score: no point
    assert risk["change"] == -30.0
    assert len(S._points(NOW)) == 19

    comp = out["compliance"]
    assert comp["points"][-1]["value"] == 80.0 and comp["points"][-1]["assets"] == 2   # (70 + 90) / 2
    assert comp["change"] == -10.0                                                     # 90 thirty days ago


def test_top_assets_main_factor(db):
    admin = _user(db)
    a = _asset(db, "dash-top-core")
    db.add(AssetRiskScore(asset_id=a.id, final_risk_score=99.5, risk_level="critical", cve_kev_count=1,
                          criticality_contribution=10, zone_contribution=5, vulnerability_contribution=35))
    db.flush()
    top = S.top_assets(db, admin)
    row = next(r for r in top if r["asset_id"] == a.id)
    assert row["main_factor"] == "vulnerability" and row["main_factor_share"] == 70 and row["kev"] == 1
    assert top[0]["score"] >= row["score"] and len(top) <= S.TOP_ASSETS


def test_route_answers_any_signed_in_user(db):
    from app.modules.dashboard.overview_router import dashboard_overview
    guest = _user(db, role=UserRole.GUEST)
    out = dashboard_overview(current_user=guest, db=db)
    assert set(out) == {"generated_at", "assets", "attention", "coverage", "trend", "top_assets"}
