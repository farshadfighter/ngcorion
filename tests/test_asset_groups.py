"""
Tags, asset groups, credential profiles and group audit runs (app/modules/asset_groups), and
scheduled group audits.

Needs a migrated PostgreSQL database; each test runs inside a transaction that is rolled back. The
group-run worker's own database sessions are pointed at the test session, and the audit itself
(run_audit) is replaced, so no device is contacted.
"""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.core.credential_crypto import PURPOSE_CREDENTIAL_PROFILES, decrypt
from app.core.database import engine
from app.models import Asset, AssetType, User, UserPermission, UserRole
from app.models.asset_groups import AssetGroup, AssetTag, CredentialProfile, GroupRun, GroupRunItem
from app.models.enums import StatusEnum
from app.models.risk import AssetRiskProfile, RiskZone
from app.models.scheduling import ScheduledJob
from app.models.security_audit_log import AuditLog
from app.models.user_permission import ModuleEnum
from app.modules.alerts import events as alert_events
from app.modules.asset_groups import groups as G
from app.modules.asset_groups import profiles as P
from app.modules.asset_groups import router as AR
from app.modules.asset_groups import runs as R
from app.modules.scheduling import audit_dispatch
from app.modules.scheduling.schemas import ScheduledJobCreate
from app.modules.scheduling.service import SchedulingService

REQ = SimpleNamespace(client=SimpleNamespace(host="10.9.9.9"), headers={})


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


class _Shared:
    """The worker opens its own sessions; in a test they are the test session (close is a no-op)."""
    def __init__(self, s):
        self._s = s

    def __getattr__(self, name):
        return getattr(self._s, name)

    def close(self):
        pass


@pytest.fixture
def worker_db(db, monkeypatch):
    monkeypatch.setattr(R, "SessionLocal", lambda: _Shared(db))
    return db


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def admin(db):
    u = User(username=f"ag_admin_{_n()}", hashed_password="x", role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.flush()
    return u


def _user(db, perms=()):
    u = User(username=f"ag_user_{_n()}", hashed_password="x", role=UserRole.USER, is_active=True)
    db.add(u)
    db.flush()
    for module, read, write in perms:
        db.add(UserPermission(user_id=u.id, module=module, can_read=read, can_write=write, can_delete=False))
    db.flush()
    return u


def _type(db, name="Linux Server"):
    t = AssetType(type_name=f"{name} {_n()}", category="server")
    db.add(t)
    db.flush()
    return t


def _asset(db, t, ip="10.20.0.5", **kw):
    a = Asset(asset_name=kw.pop("name", f"ag-asset-{_n()}"), asset_type_id=t.id, ip_address=ip, **kw)
    db.add(a)
    db.flush()
    return a


def _profile(db, kind="ssh", **secrets):
    data = {"name": f"profile-{_n()}", "kind": kind, "username": "auditor",
            "secrets": secrets or {"password": "S3cret-Pass!"}, "options": {}}
    p = P.create(db, data, None)
    db.flush()
    return p


# ── groups and tags ─────────────────────────────────────────────────────────

def test_dynamic_rules_select_by_type_tag_ip_name_status_and_zone(db):
    linux, router = _type(db), _type(db, "Router")
    a = _asset(db, linux, "10.20.0.5", name=f"web-01-{_n()}")
    b = _asset(db, linux, "172.16.5.9", name=f"db-01-{_n()}")
    c = _asset(db, router, "10.20.0.1")
    d = _asset(db, linux, None, status=StatusEnum.DECOMMISSIONED)
    G.add_tags(db, [a.id, b.id], [" PCI ", "web"])
    zone = RiskZone(name=f"DMZ {_n()}", score=80)
    db.add(zone)
    db.flush()
    db.add(AssetRiskProfile(asset_id=a.id, criticality_level="high", criticality_score=75, zone_id=zone.id))
    db.flush()

    def ids(rules):
        return set(G.rule_member_ids(db, G.check_rules(rules))) & {a.id, b.id, c.id, d.id}

    assert ids([{"field": "type", "op": "eq", "value": str(linux.id)}]) == {a.id, b.id, d.id}
    assert ids([{"field": "type", "op": "eq", "value": linux.id},
                {"field": "status", "op": "neq", "value": "decommissioned"}]) == {a.id, b.id}
    assert ids([{"field": "tag", "op": "has", "value": "pci"}]) == {a.id, b.id}
    assert ids([{"field": "tag", "op": "not_has", "value": "PCI"}]) == {c.id, d.id}
    assert ids([{"field": "ip", "op": "in", "value": "10.20.0.0/24"}]) == {a.id, c.id}
    assert ids([{"field": "ip", "op": "not_in", "value": "10.0.0.0/8"}]) == {b.id, d.id}
    assert ids([{"field": "name", "op": "contains", "value": "WEB-"}]) == {a.id}
    assert ids([{"field": "zone", "op": "eq", "value": zone.id}]) == {a.id}
    assert a.id not in ids([{"field": "zone", "op": "neq", "value": zone.id}])
    # tags are stored trimmed and lower case, once
    assert G.tags_of(db, [a.id])[a.id] == ["pci", "web"]
    assert G.add_tags(db, [a.id], ["pci"]) == 0
    assert G.remove_tags(db, [a.id], ["PCI"]) == 1


@pytest.mark.parametrize("rule, message", [
    ({"field": "colour", "op": "eq", "value": 1}, "Unknown condition"),
    ({"field": "type", "op": "contains", "value": 1}, "Unknown condition"),
    ({"field": "ip", "op": "in", "value": "10.0.0.0/33"}, "Not an IP range"),
    ({"field": "status", "op": "eq", "value": "broken"}, "Unknown status"),
    ({"field": "zone", "op": "eq", "value": "x"}, "Choose a value"),
    ({"field": "tag", "op": "has", "value": "x" * 65}, "1 to 64"),
])
def test_rules_that_cannot_be_evaluated_are_refused(rule, message):
    with pytest.raises(G.RuleError, match=message):
        G.check_rules([rule])


def test_group_api_static_and_dynamic(db, admin):
    t = _type(db)
    a, b = _asset(db, t), _asset(db, t)
    out = AR.create_group(AR.GroupBody(name=f"static-{_n()}", kind="static", asset_ids=[a.id, 999999999]),
                          REQ, admin, db)
    assert out["asset_count"] == 1
    assert AR.change_members(out["id"], AR.MembersBody(asset_ids=[b.id]), REQ, admin, db)["asset_count"] == 2
    detail = AR.get_group(out["id"], admin, db)
    assert {x["id"] for x in detail["assets"]} == {a.id, b.id}
    with pytest.raises(HTTPException) as exc:
        AR.create_group(AR.GroupBody(name=detail["name"]), REQ, admin, db)
    assert exc.value.status_code == 409

    dyn = AR.create_group(AR.GroupBody(name=f"dyn-{_n()}", rules=[
        AR.Rule(field="type", op="eq", value=t.id)]), REQ, admin, db)
    assert dyn["asset_count"] == 2
    c = _asset(db, t)                                   # a new matching asset is a member at once
    assert c.id in G.member_ids(db, db.get(AssetGroup, dyn["id"]))
    with pytest.raises(HTTPException) as exc:
        AR.change_members(dyn["id"], AR.MembersBody(asset_ids=[a.id]), REQ, admin, db)
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        AR.preview(AR.PreviewBody(rules=[AR.Rule(field="ip", op="in", value="nonsense")]), admin, db)
    assert exc.value.status_code == 400
    assert AR.preview(AR.PreviewBody(rules=[AR.Rule(field="type", op="eq", value=t.id)]), admin, db)["count"] == 3
    assert db.query(AuditLog).filter(AuditLog.action == "asset_group.create", AuditLog.user_id == admin.id).count() == 2


def test_bulk_edit(db, admin):
    t = _type(db)
    a, b = _asset(db, t), _asset(db, t)
    assert AR.bulk_edit(AR.BulkBody(asset_ids=[a.id, b.id], action="add_tags", tags=["Prod"]), REQ, admin, db) \
        == {"changed": 2}
    assert db.query(AssetTag).filter(AssetTag.asset_id.in_([a.id, b.id]), AssetTag.tag == "prod").count() == 2
    AR.bulk_edit(AR.BulkBody(asset_ids=[a.id, b.id], action="set_status", value="standby"), REQ, admin, db)
    db.refresh(a)
    assert a.status == StatusEnum.STANDBY
    zone = RiskZone(name=f"Core {_n()}", score=40)
    db.add(zone)
    db.flush()
    assert AR.bulk_edit(AR.BulkBody(asset_ids=[a.id], action="set_zone", value=zone.id), REQ, admin, db)["changed"] == 1
    assert db.query(AssetRiskProfile).filter(AssetRiskProfile.asset_id == a.id).one().zone_id == zone.id
    with pytest.raises(HTTPException) as exc:     # the typed count must match
        AR.bulk_edit(AR.BulkBody(asset_ids=[a.id, b.id], action="delete", confirm_count=1), REQ, admin, db)
    assert exc.value.status_code == 400
    out = AR.bulk_edit(AR.BulkBody(asset_ids=[a.id, b.id], action="delete", confirm_count=2), REQ, admin, db)
    assert out["deleted"] == 2 and db.get(Asset, a.id) is None


def test_bulk_delete_and_zone_need_their_own_permissions(db):
    t = _type(db)
    a = _asset(db, t)
    u = _user(db, [(ModuleEnum.ASSET_LIST, True, True)])
    for body in (AR.BulkBody(asset_ids=[a.id], action="delete", confirm_count=1),
                 AR.BulkBody(asset_ids=[a.id], action="set_zone", value=None)):
        with pytest.raises(HTTPException) as exc:
            AR.bulk_edit(body, REQ, u, db)
        assert exc.value.status_code == 403


# ── credential profiles ─────────────────────────────────────────────────────

def test_profile_secrets_are_encrypted_and_never_returned(db, admin):
    out = AR.create_profile(AR.ProfileBody(name=f"linux-{_n()}", kind="ssh", username="audit",
                                           secrets={"password": "Pw-One-2026", "sudo_password": "Sudo-2026"},
                                           options={"port": 2222}), REQ, admin, db)
    row = db.get(CredentialProfile, out["id"])
    assert "Pw-One-2026" not in row.secrets_encrypted
    assert json.loads(decrypt(row.secrets_encrypted, PURPOSE_CREDENTIAL_PROFILES))["password"] == "Pw-One-2026"
    listed = AR.list_profiles(admin, db)
    blob = json.dumps(listed, default=str)
    assert "Pw-One-2026" not in blob and "Sudo-2026" not in blob
    mine = next(p for p in listed if p["id"] == out["id"])
    assert mine["secrets_set"] == ["password", "sudo_password"] and mine["options"]["port"] == 2222

    # an empty secret keeps the stored one; the age restarts only when a secret changes
    before = row.secrets_changed_at
    AR.update_profile(row.id, AR.ProfileBody(name=row.name, kind="ssh", username="audit",
                                             secrets={"password": ""}, description="x"), REQ, admin, db)
    assert P.secrets_of(row)["password"] == "Pw-One-2026" and row.secrets_changed_at == before
    AR.update_profile(row.id, AR.ProfileBody(name=row.name, kind="ssh", username="audit",
                                             secrets={"password": "Pw-Two-2026"}), REQ, admin, db)
    assert P.secrets_of(row)["password"] == "Pw-Two-2026" and row.secrets_changed_at > before
    details = [r.detail for r in db.query(AuditLog).filter(AuditLog.target_id == row.id,
                                                           AuditLog.module == "credential_profiles")]
    assert any("Changed the sign-in details" in d for d in details)
    assert not any("Pw-" in (d or "") for d in details)
    with pytest.raises(HTTPException):
        AR.create_profile(AR.ProfileBody(name="no-password", kind="ssh", username="x"), REQ, admin, db)


def test_params_for_each_technology(db):
    ssh = _profile(db, "ssh", password="pw", sudo_password="sudo", enable_secret="en", db_password="dbpw")
    ssh.options = {"port": 2200, "db_username": "dba", "db_port": None}
    cisco = P.params_for("cisco", ssh, "L1", "job")
    assert cisco == {"ssh_username": "auditor", "ssh_password": "pw", "ssh_port": 2200, "ssh_secret": "en",
                     "profile": "L1", "job_name": "job"}
    linux = P.params_for("linux", ssh)
    assert linux["sudo_password"] == "sudo" and "ssh_secret" not in linux
    assert P.params_for("mongodb", ssh)["mongo_username"] == "dba"
    mysql = P.params_for("mysql", ssh)
    assert mysql["mysql_password"] == "dbpw" and mysql["mysql_port"] == 3306
    win = _profile(db, "winrm")
    win.options = {"port": 5986, "transport": "kerberos", "verify_ssl": True}
    assert P.params_for("iis", win)["transport"] == "kerberos"
    assert P.params_for("windows", win)["winrm_port"] == 5986
    assert P.params_for("mssql", _profile(db, "mssql"))["mssql_port"] == 1433
    assert P.params_for("sophos", _profile(db, "sophos_api"))["sophos_port"] == 4444
    with pytest.raises(P.ProfileError):
        P.params_for("windows", ssh)
    # every technology a profile can sign in to takes these arguments
    for tech, kind in P.TECH_KIND.items():
        assert tech in audit_dispatch.SUPPORTED_TECHNOLOGIES
        prof = {"ssh": ssh, "winrm": win}.get(kind) or _profile(db, kind)
        params = P.params_for(tech, prof)
        assert audit_dispatch.REQUIRED_PARAMS[tech] <= params.keys(), tech


def test_only_admins_define_profiles_and_use_needs_permission(db):
    from app.core.dependencies import require_admin, require_permission
    plain = _user(db, [(ModuleEnum.AUDITING, True, True)])
    with pytest.raises(HTTPException):
        require_admin(plain)
    with pytest.raises(HTTPException) as exc:
        require_permission("CREDENTIAL_PROFILES", "read")(current_user=plain, db=db)
    assert exc.value.status_code == 403
    user = _user(db, [(ModuleEnum.AUDITING, True, True), (ModuleEnum.CREDENTIAL_PROFILES, True, False)])
    assert require_permission("CREDENTIAL_PROFILES", "read")(current_user=user, db=db) is user


def test_rotation_reminder(db):
    p = _profile(db)
    assert p not in P.rotation_due(db)
    p.secrets_changed_at = datetime.now(timezone.utc) - timedelta(days=91)
    db.flush()
    assert p in P.rotation_due(db)
    assert P.public(p)["rotation_due"]
    problems = alert_events._credential_rotation(db, {}, datetime.now(), datetime.now())
    assert any(x.key == f"credential_profile:{p.id}" for x in problems)


# ── group runs ──────────────────────────────────────────────────────────────

def _group(db, assets):
    g = AssetGroup(name=f"g-{_n()}", kind="static")
    db.add(g)
    db.flush()
    for a in assets:
        db.add(G.AssetGroupMember(group_id=g.id, asset_id=a.id))
    db.flush()
    return g


def _session(status="completed", error=None, pct=82.5):
    return SimpleNamespace(id=4242, status=status, compliance_pct=pct, connection_error=error)


def _drain(db):
    """Sweep and run each claimed item, as the worker does, until nothing is left."""
    for _ in range(20):
        ids = R.sweep(db)
        for i in ids:
            R.run_item(i)
        if not ids:
            R.sweep(db)
            return


def test_group_run_outcomes(worker_db, admin, monkeypatch):
    db = worker_db
    t = _type(db)
    ok, refused, down, boom, noaddr = (_asset(db, t, f"10.30.0.{i}") for i in range(1, 6))
    noaddr.ip_address = None
    db.flush()
    calls = []

    def fake_run_audit(technology, _db, asset_id, user_id, params):
        calls.append((technology, asset_id, user_id, params))
        if asset_id == ok.id:
            return _session()
        if asset_id == refused.id:
            return _session("failed", "SSHAuthenticationError: Authentication failed for 10.30.0.2", None)
        if asset_id == down.id:
            raise ConnectionError("Connection to 10.30.0.3 timed out")
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(audit_dispatch, "run_audit", fake_run_audit)
    prof = _profile(db)
    run = R.start_run(db, _group(db, [ok, refused, down, boom, noaddr]), "linux", prof, "L1", 2, admin)
    db.flush()
    first = R.sweep(db)
    assert len(first) == 2                          # concurrency 2
    assert db.get(GroupRun, run.id).status == "running"
    for i in first:
        R.run_item(i)
    _drain(db)
    db.refresh(run)
    items = {i.asset_id: i for i in run.items}
    assert run.status == "done" and run.finished_at is not None
    assert (items[ok.id].status, items[ok.id].session_id, items[ok.id].compliance) == ("done", 4242, 82.5)
    assert (items[refused.id].status, items[refused.id].reason) == ("failed", "auth")
    assert (items[down.id].status, items[down.id].reason) == ("failed", "unreachable")
    assert (items[boom.id].status, items[boom.id].reason) == ("failed", "error")
    assert (items[noaddr.id].status, items[noaddr.id].reason) == ("skipped", "no_address")
    assert len(calls) == 4 and all(c[0] == "linux" and c[2] == admin.id for c in calls)
    assert calls[0][3]["ssh_password"] == "S3cret-Pass!" and calls[0][3]["profile"] == "L1"
    assert db.get(CredentialProfile, prof.id).last_used_at is not None

    # the failure alert, and retrying only the failed assets
    problems = alert_events._group_run_failed(db, {}, datetime.now(), datetime.now(timezone.utc) - timedelta(minutes=5))
    assert any(p.key == f"group_run:{run.id}" and "3 asset(s)" in p.detail for p in problems)
    calls.clear()
    assert R.retry_failed(db, run) == 3
    _drain(db)
    assert sorted(c[1] for c in calls) == sorted([refused.id, down.id, boom.id])
    assert db.get(GroupRunItem, items[boom.id].id).attempts == 2


def test_group_run_license_stop_and_restart(worker_db, admin, monkeypatch):
    from app.core import license_state
    db = worker_db
    t = _type(db)
    assets = [_asset(db, t, f"10.31.0.{i}") for i in range(1, 5)]
    monkeypatch.setattr(audit_dispatch, "run_audit", lambda *a, **k: _session())
    run = R.start_run(db, _group(db, assets), "linux", _profile(db), None, 1, admin)
    db.flush()

    # a license that covers no asset: the first one is skipped, not audited
    license_state.set_license_state({"valid": True, "message": "t", "plan_code": "X", "plan_name": "X",
                                     "is_pilot_mode": False, "limits": {"max_assets": 0, "addon_packs": 0}})
    [first] = R.sweep(db)
    R.run_item(first)
    assert (db.get(GroupRunItem, first).status, db.get(GroupRunItem, first).reason) == ("skipped", "license")

    # NGCorion restarts while one is running; then the run is stopped
    [second] = R.sweep(db)
    assert R.recover_interrupted(db) == 1
    assert db.get(GroupRunItem, second).reason == "interrupted"
    R.stop(db, run)
    R.sweep(db)
    db.refresh(run)
    assert run.status == "stopped"
    assert sorted(i.status for i in run.items) == ["cancelled", "cancelled", "failed", "skipped"]
    with pytest.raises(R.RunError):
        R.start_run(db, _group(db, []), "linux", _profile(db), None, 1, admin)
    with pytest.raises(R.RunError):
        R.start_run(db, _group(db, assets), "windows", _profile(db), None, 1, admin)


def test_group_run_api(db, admin):
    t = _type(db)
    g = _group(db, [_asset(db, t)])
    prof = _profile(db)
    out = AR.start_run(AR.RunBody(group_id=g.id, technology="linux", credential_profile_id=prof.id), REQ, admin, db)
    assert out["total"] == 1 and out["status"] == "queued"
    assert AR.get_run(out["id"], admin, db)["items"][0]["status"] == "queued"
    assert AR.stop_run(out["id"], REQ, admin, db)["status"] == "stopping"
    log = db.query(AuditLog).filter(AuditLog.action == "group_run.start", AuditLog.target_id == out["id"]).one()
    assert prof.name in log.detail and "S3cret" not in log.detail
    # the profile and the group cannot be deleted while a run uses them
    with pytest.raises(HTTPException) as exc:
        AR.delete_profile(prof.id, REQ, admin, db)
    assert exc.value.status_code == 409
    with pytest.raises(HTTPException) as exc:
        AR.delete_group(g.id, REQ, admin, db)
    assert exc.value.status_code == 409

    no_profiles = _user(db, [(ModuleEnum.AUDITING, True, True)])
    with pytest.raises(HTTPException) as exc:
        AR.start_run(AR.RunBody(group_id=g.id, technology="linux", credential_profile_id=prof.id),
                     REQ, no_profiles, db)
    assert exc.value.status_code == 403


def test_scheduled_group_audit(db, admin):
    t = _type(db)
    g = _group(db, [_asset(db, t), _asset(db, t)])
    prof = _profile(db)
    job = SchedulingService.create_job(db, ScheduledJobCreate(
        job_name="nightly linux", job_type="audit", technology="linux", group_id=g.id,
        credential_profile_id=prof.id, concurrency=5, audit_profile="FULL", recurrence="daily", hour=2), admin.id)
    assert job.asset_id is None and job.group_id == g.id and job.concurrency == 5
    run_row = SchedulingService.run_job_now(db, job)
    assert run_row.status == "success" and run_row.result_ref.startswith("group_run:")
    group_run = db.get(GroupRun, int(run_row.result_ref.split(":")[1]))
    assert group_run.scheduled_job_id == job.id and group_run.audit_profile == "FULL"
    assert group_run.started_by == admin.id and len(group_run.items) == 2
    # a profile used by a schedule cannot be deleted
    group_run.status = "done"
    db.flush()
    with pytest.raises(HTTPException) as exc:
        AR.delete_profile(prof.id, REQ, admin, db)
    assert exc.value.status_code == 409
    with pytest.raises(ValueError, match="credential_profile_id"):
        SchedulingService.create_job(db, ScheduledJobCreate(
            job_name="x", job_type="audit", technology="linux", group_id=g.id, recurrence="daily", hour=2), admin.id)


def test_migration_matches_models(db):
    cols = {r[0] for r in db.execute(text(
        "select column_name from information_schema.columns where table_name = 'scheduled_jobs'"))}
    assert {"group_id", "credential_profile_id", "concurrency"} <= cols
    assert db.query(ScheduledJob).filter(ScheduledJob.group_id.isnot(None)).count() >= 0
