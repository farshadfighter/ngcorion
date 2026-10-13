"""
Scheduled configuration backups and change tracking (app/modules/backup/changes.py, collect.py,
retention.py, group runs of kind "backup", scheduled backup jobs, the change alerts).

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back. Devices
are not contacted: take_backup is replaced.
"""
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserPermission, UserRole
from app.models.asset_groups import AssetGroup, AssetGroupMember, GroupRun
from app.models.backup import DeviceBackup
from app.models.backup_restore import BackupRestore
from app.models.user_permission import ModuleEnum
from app.modules.alerts import events as alert_events
from app.modules.asset_groups import profiles as P
from app.modules.asset_groups import router as AR
from app.modules.asset_groups import runs as R
import importlib

from app.modules.backup import changes, collect, retention
from app.modules.scheduling.schemas import ScheduledJobCreate
from app.modules.scheduling.service import SchedulingService

BR = importlib.import_module("app.modules.backup.router")
REQ = SimpleNamespace(client=SimpleNamespace(host="10.9.9.9"), headers={})

CISCO = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:00:00 UTC Mon Sep 1 2026
!
hostname Core-SW-01
!
interface GigabitEthernet0/1
 description Uplink
 ip address 10.0.1.2 255.255.255.0
!
line vty 0 4
 transport input ssh
!
logging host 10.0.0.9
end
"""
# the same device captured later: only the byte count and the timestamp differ
CISCO_SAME = CISCO.replace("1234 bytes", "1301 bytes").replace("10:00:00", "23:59:59")
# changed: telnet allowed on the vty lines, the syslog server removed
CISCO_CHANGED = CISCO.replace(" transport input ssh", " transport input ssh telnet").replace("logging host 10.0.0.9\n", "")

BUNDLE_OLD = """##### BEGIN FILE: /etc/ssh/sshd_config #####
PermitRootLogin no
PasswordAuthentication no
##### END FILE: /etc/ssh/sshd_config #####
"""


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


class _Shared:
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
    u = User(username=f"bk_admin_{_n()}", hashed_password="x", role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db, ip="10.40.0.1"):
    t = AssetType(type_name=f"Cisco Switch {_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"sw-{_n()}", asset_type_id=t.id, ip_address=ip)
    db.add(a)
    db.flush()
    return a


def _backup(db, asset, text, source="manual", when=None):
    b = DeviceBackup(asset_id=asset.id, asset_name=asset.asset_name, device_ip=asset.ip_address,
                     device_type="cisco", config_content=text, source=source,
                     created_at=when or datetime.utcnow())
    db.add(b)
    db.flush()
    return b


# ── comparing versions ──────────────────────────────────────────────────────

def test_compare_ignores_capture_noise_and_shows_real_changes():
    assert changes.compare("cisco", CISCO, CISCO_SAME).is_empty
    diff = changes.compare("cisco", CISCO, CISCO_CHANGED)
    plus = [line.text.strip() for s in diff.sections for line in s.lines if line.op == "+"]
    minus = [line.text.strip() for s in diff.sections for line in s.lines if line.op == "-"]
    assert any("telnet" in t for t in plus)
    assert any("logging host 10.0.0.9" in t for t in minus)
    assert diff.added >= 1 and diff.removed >= 1


def test_compare_file_bundles_and_plain_text():
    new = BUNDLE_OLD.replace("PermitRootLogin no", "PermitRootLogin yes")
    diff = changes.compare("linux", BUNDLE_OLD, new)
    assert diff.sections[0].title == "/etc/ssh/sshd_config"
    assert (diff.added, diff.removed) == (1, 1)
    added_file = new + "##### BEGIN FILE: /etc/motd #####\nhello\n##### END FILE: /etc/motd #####\n"
    assert any("new file" in s.title for s in changes.compare("linux", BUNDLE_OLD, added_file).sections)
    text = changes.compare("unknown", "a\nb\n", "a\nc\n")
    assert (text.added, text.removed) == (1, 1)
    assert changes.compare("unknown", "same", "same").is_empty


def test_every_saved_backup_is_compared_with_the_previous_one(db):
    a = _asset(db)
    first = _backup(db, a, CISCO, when=datetime.utcnow() - timedelta(days=2))
    assert first.change_origin == "first" and first.changed is None
    same = _backup(db, a, CISCO_SAME, when=datetime.utcnow() - timedelta(days=1))
    assert (same.changed, same.change_origin, same.previous_backup_id) == (False, "unchanged", first.id)
    changed = _backup(db, a, CISCO_CHANGED)
    assert changed.changed is True and changed.change_origin == "external"
    assert changed.added_lines >= 1 and changed.removed_lines >= 1


def test_a_change_made_by_ngcorion_is_told_apart(db, admin):
    a = _asset(db)
    _backup(db, a, CISCO, when=datetime.utcnow() - timedelta(hours=3))
    r = BackupRestore(asset_id=a.id, asset_name=a.asset_name, device_ip=a.ip_address, device_type="cisco",
                      status="succeeded", reason="roll back", revert_minutes=10, events=[], requested_by=admin.id,
                      created_at=datetime.utcnow() - timedelta(hours=2),
                      finished_at=datetime.utcnow() - timedelta(hours=2))
    db.add(r)
    db.flush()
    b = _backup(db, a, CISCO_CHANGED)
    assert (b.change_origin, b.change_ref) == ("ngcorion", f"restore:{r.id}")


# ── backup runs ─────────────────────────────────────────────────────────────

def _group(db, assets):
    g = AssetGroup(name=f"bkg-{_n()}", kind="static")
    db.add(g)
    db.flush()
    for a in assets:
        db.add(AssetGroupMember(group_id=g.id, asset_id=a.id))
    db.flush()
    return g


def _profile(db):
    p = P.create(db, {"name": f"bkp-{_n()}", "kind": "ssh", "username": "backup",
                      "secrets": {"password": "Pw-2026!", "enable_secret": "En-2026!"}, "options": {"port": 2201}}, None)
    db.flush()
    return p


def _drain(db):
    for _ in range(20):
        ids = R.sweep(db)
        for i in ids:
            R.run_item(i)
        if not ids:
            R.sweep(db)
            return


def test_backup_runs_store_only_changes(worker_db, admin, monkeypatch):
    db = worker_db
    ok, refused = _asset(db, "10.40.0.2"), _asset(db, "10.40.0.3")
    config = {"text": CISCO}
    calls = []

    def fake_take(family, ip, username, password, secret=None, port=22):
        calls.append((family, ip, username, password, secret, port))
        if ip == "10.40.0.3":
            from app.core.ssh_exceptions import SSHAuthenticationError
            raise SSHAuthenticationError("Authentication failed for 10.40.0.3")
        return config["text"]

    monkeypatch.setattr(collect, "take_backup", fake_take)
    g, prof = _group(db, [ok, refused]), _profile(db)

    def run_once():
        run = R.start_run(db, g, "cisco", prof, None, 5, admin, kind="backup")
        db.flush()
        _drain(db)
        db.refresh(run)
        return run, {i.asset_id: i for i in run.items}

    run, items = run_once()
    assert run.status == "done" and run.kind == "backup"
    assert (items[ok.id].status, items[ok.id].outcome) == ("done", "first")
    assert (items[refused.id].status, items[refused.id].reason) == ("failed", "auth")
    assert calls[0] == ("cisco", "10.40.0.2", "backup", "Pw-2026!", "En-2026!", 2201)
    stored = db.get(DeviceBackup, items[ok.id].backup_id)
    assert (stored.source, stored.group_run_id) == ("scheduled", run.id)

    config["text"] = CISCO_SAME
    run2, items2 = run_once()
    assert items2[ok.id].outcome == "unchanged" and items2[ok.id].backup_id == stored.id
    db.refresh(stored)
    assert stored.confirmed_at is not None
    assert db.query(DeviceBackup).filter(DeviceBackup.asset_id == ok.id).count() == 1

    config["text"] = CISCO_CHANGED
    run3, items3 = run_once()
    assert items3[ok.id].outcome == "changed"
    newest = db.get(DeviceBackup, items3[ok.id].backup_id)
    assert newest.change_origin == "external" and newest.previous_backup_id == stored.id

    problems = alert_events._config_changed_external(db, {}, datetime.utcnow(), datetime.utcnow() - timedelta(minutes=5))
    assert any(p.key == f"backup:{newest.id}" for p in problems)
    failed = alert_events._group_backup_failed(db, {}, datetime.utcnow(), datetime.utcnow() - timedelta(minutes=5))
    assert any(p.key == f"group_run:{run.id}" and p.title == "Group backup finished with failures" for p in failed)
    # a backup run is not reported as a failed group audit
    audits = alert_events._group_run_failed(db, {}, datetime.utcnow(), datetime.utcnow() - timedelta(minutes=5))
    assert not any(p.key == f"group_run:{run.id}" for p in audits)

    with pytest.raises(R.RunError):
        R.start_run(db, g, "windows", prof, None, 5, admin, kind="backup")


def test_backup_run_api_permissions_and_compare(db, admin):
    a = _asset(db)
    old = _backup(db, a, CISCO, when=datetime.utcnow() - timedelta(days=1))
    new = _backup(db, a, CISCO_CHANGED)
    out = BR.compare_backups(old=new.id, new=old.id, current_user=admin, db=db)   # order does not matter
    assert out.old.id == old.id and out.new.id == new.id and out.added >= 1
    other = _backup(db, _asset(db), CISCO)
    with pytest.raises(HTTPException) as exc:
        BR.compare_backups(old=old.id, new=other.id, current_user=admin, db=db)
    assert exc.value.status_code == 400

    g, prof = _group(db, [a]), _profile(db)
    started = AR.start_run(AR.RunBody(group_id=g.id, kind="backup", technology="cisco",
                                      credential_profile_id=prof.id), REQ, admin, db)
    assert started["kind"] == "backup"
    assert [r["id"] for r in AR.list_runs(kind="backup", limit=100, current_user=admin, db=db)] == [started["id"]]
    assert started["id"] not in [r["id"] for r in AR.list_runs(kind="audit", limit=100, current_user=admin, db=db)]

    auditor = User(username=f"bk_aud_{_n()}", hashed_password="x", role=UserRole.USER, is_active=True)
    db.add(auditor)
    db.flush()
    db.add(UserPermission(user_id=auditor.id, module=ModuleEnum.AUDITING, can_read=True, can_write=True,
                          can_delete=False))
    db.flush()
    with pytest.raises(HTTPException) as exc:
        AR.list_runs(kind="backup", limit=100, current_user=auditor, db=db)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        AR.get_run(started["id"], current_user=auditor, db=db)
    assert exc.value.status_code == 403


def test_retention_removes_only_old_duplicates(db, admin):
    a = _asset(db)
    long_ago = datetime.utcnow() - timedelta(days=200)
    first = _backup(db, a, CISCO, when=long_ago)
    dup = _backup(db, a, CISCO_SAME, when=long_ago + timedelta(days=1))           # identical: may go
    change = _backup(db, a, CISCO_CHANGED, when=long_ago + timedelta(days=2))     # a change: kept
    latest_dup = _backup(db, a, CISCO_CHANGED.replace("1234 bytes", "999 bytes"))  # latest: kept
    assert dup.changed is False and change.changed is True
    assert retention.prune(db) == 1
    left = {r[0] for r in db.query(DeviceBackup.id).filter(DeviceBackup.asset_id == a.id)}
    assert left == {first.id, change.id, latest_dup.id}
    assert retention.save_settings(db, 3, admin.id)["retention_days"] == retention.MIN_DAYS


def test_scheduled_backup_job(db, admin):
    a = _asset(db)
    g, prof = _group(db, [a]), _profile(db)
    job = SchedulingService.create_job(db, ScheduledJobCreate(
        job_name="nightly switches", job_type="backup", technology="cisco", group_id=g.id,
        credential_profile_id=prof.id, recurrence="daily", hour=2), admin.id)
    assert job.job_type == "backup" and job.asset_id is None and job.hour == 2
    run_row = SchedulingService.run_job_now(db, job)
    assert run_row.status == "success" and run_row.result_ref.startswith("group_run:")
    assert db.get(GroupRun, int(run_row.result_ref.split(":")[1])).kind == "backup"
    with pytest.raises(ValueError):
        SchedulingService.create_job(db, ScheduledJobCreate(
            job_name="x", job_type="backup", technology="windows", group_id=g.id,
            credential_profile_id=prof.id, recurrence="daily", hour=2), admin.id)


def test_overview_counts_a_confirmed_backup_as_fresh(db):
    from app.modules.backup.overview import compute_overview
    a = _asset(db)
    a.manufacturer = "Cisco"
    b = _backup(db, a, CISCO, when=datetime.utcnow() - timedelta(days=60))
    b.confirmed_at = datetime.utcnow()
    db.flush()
    attention = {d["asset_id"] for d in compute_overview(db)["attention"]}
    assert a.id not in attention          # 60 days old, but confirmed unchanged today
