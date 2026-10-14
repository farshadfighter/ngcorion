"""
Configuration changes reported over syslog (app/modules/syslog/config_changes.py): recognising the
messages, recording them in the intake, backing the device up with its scheduled backup's
credential profile once it has been quiet, who changed it and from where on the backup and the alert,
the alert for devices without a scheduled backup, the off switch, the asset timeline and retention.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back. Devices
are not contacted: take_backup is replaced.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.asset_groups import AssetGroup, AssetGroupMember, GroupRun
from app.models.backup import DeviceBackup
from app.models.scheduling import ScheduledJob
from app.models.security_audit_log import AuditLog
from app.models.syslog import ConfigChangeEvent
from app.modules.alerts import events as alert_events
from app.modules.asset_groups import profiles as P
from app.modules.asset_groups import runs as R
from app.modules.assets import overview360
from app.modules.backup import collect
from app.modules.syslog import config_changes as C
from app.modules.syslog import intake as I
from app.modules.syslog import retention
from app.modules.backup.router import list_backups

CISCO = "hostname sw\n!\ninterface Gi0/1\n description uplink\n!\nline vty 0 4\n transport input ssh\nend\n"
CISCO_CHANGED = CISCO.replace("transport input ssh", "transport input ssh telnet")


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
    u = User(username=f"cc_admin_{_n()}", hashed_password="x", role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db, ip):
    t = AssetType(type_name=f"Cisco Switch {_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"sw-{_n()}", asset_type_id=t.id, ip_address=ip)
    db.add(a)
    db.flush()
    return a


def _schedule(db, admin, assets, enabled=True):
    g = AssetGroup(name=f"ccg-{_n()}", kind="static")
    db.add(g)
    db.flush()
    for a in assets:
        db.add(AssetGroupMember(group_id=g.id, asset_id=a.id))
    prof = P.create(db, {"name": f"ccp-{_n()}", "kind": "ssh", "username": "backup",
                         "secrets": {"password": "Pw-2026!"}, "options": {}}, None)
    db.flush()
    job = ScheduledJob(job_name=f"Nightly backup {_n()}", job_type="backup", technology="cisco", group_id=g.id,
                       credential_profile_id=prof.id, concurrency=5, params_encrypted="x", recurrence="daily",
                       hour=2, minute=0, enabled=enabled, next_run_at=datetime.utcnow() + timedelta(hours=8),
                       created_by=admin.id)
    db.add(job)
    db.flush()
    return job


def _event(db, asset, by="netadmin", source="10.20.0.9", ago=120, message="Configured from console"):
    e = ConfigChangeEvent(asset_id=asset.id, received_at=datetime.utcnow() - timedelta(seconds=ago),
                          message=message, changed_by=by, changed_from=source, status="pending")
    db.add(e)
    db.flush()
    return e


def _drain(db):
    for _ in range(20):
        ids = R.sweep(db)
        for i in ids:
            R.run_item(i)
        if not ids:
            R.sweep(db)
            return


# ── recognising the messages ────────────────────────────────────────────────

def test_detects_cisco_and_fortigate_changes():
    c = C.detect("<189>52: *Mar  1 00:10:12.345: %SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.20.0.9)")
    assert (c.by, c.source) == ("netadmin", "10.20.0.9") and c.message.startswith("Configured from console")
    c = C.detect("<189>Oct 14 10:00:01 sw1 %SYS-5-CONFIG_I: Configured from console by admin on console")
    assert (c.by, c.source) == ("admin", "console")
    c = C.detect("<189>2026 Oct 14 10:00:01 nx1 %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by admin on 10.1.1.5@pts/0")
    assert (c.by, c.source) == ("admin", "10.1.1.5")
    # the start-up configuration loaded at boot is not a change
    assert C.detect("%SYS-5-CONFIG_I: Configured from memory by console") is None
    c = C.detect('<189>date=2026-10-14 time=10:00:01 devname="fgt" logid="0100044547" type="event" '
                 'logdesc="Object attribute configured" user="admin" ui="GUI(10.0.0.8)" cfgpath="firewall.policy" '
                 'msg="Edit firewall.policy 3"')
    assert (c.by, c.source, c.message) == ("admin", "10.0.0.8", "Edit firewall.policy 3 (firewall.policy)")
    c = C.detect('<189>logid="0100032102" logdesc="Configuration changed" user="ops" ui="ssh(10.0.0.7)"')
    assert (c.by, c.source) == ("ops", "10.0.0.7")
    assert C.detect('<189>logid="0100032001" logdesc="Admin login successful" user="admin" ui="ssh(10.0.0.7)"') is None
    assert C.detect("<14>Oct 14 10:00:01 web1 sshd[1]: Accepted publickey for root") is None
    assert C.detect("") is None


def test_the_intake_records_changes_whatever_the_severity_kept(db):
    a = _asset(db, "10.61.0.1")
    i = I.Intake(store_max_severity=3)          # notices (level 5) are not stored as messages
    i.assets = {"10.61.0.1": a.id}
    raw = b"<189>%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.20.0.9)"
    assert i.accept(raw, "10.61.0.1", "udp") is False
    assert i.accept(b"<189>%SYS-5-CONFIG_I: Configured from console by x on vty0", "10.99.0.1", "udp") is False
    assert len(i.changes) == 1
    i.drain(db)
    rows = db.query(ConfigChangeEvent).filter(ConfigChangeEvent.asset_id == a.id).all()
    assert [(r.changed_by, r.changed_from, r.status) for r in rows] == [("netadmin", "10.20.0.9", "pending")]
    assert i.changes == []


# ── backing up ──────────────────────────────────────────────────────────────

def test_a_reported_change_backs_the_device_up(worker_db, admin, monkeypatch):
    db = worker_db
    sw, other = _asset(db, "10.61.1.1"), _asset(db, "10.61.1.2")
    job = _schedule(db, admin, [sw, other])
    db.add(DeviceBackup(asset_id=sw.id, asset_name=sw.asset_name, device_ip=sw.ip_address, device_type="cisco",
                        config_content=CISCO, source="scheduled", created_at=datetime.utcnow() - timedelta(days=1)))
    db.flush()
    calls = []
    monkeypatch.setattr(collect, "take_backup", lambda fam, ip, *a, **k: calls.append(ip) or CISCO_CHANGED)
    _event(db, sw, by="netadmin", source="10.20.0.9", ago=150)
    _event(db, sw, by="ops", source="10.20.0.10", ago=90)

    out = C.process(db)
    assert out["started"] == 1
    run = db.query(GroupRun).filter(GroupRun.trigger == "syslog").order_by(GroupRun.id.desc()).first()
    assert run.kind == "backup" and run.scheduled_job_id == job.id and run.concurrency == 1
    assert [i.asset_id for i in run.items] == [sw.id]           # only the device that reported
    assert {e.status for e in db.query(ConfigChangeEvent).filter(ConfigChangeEvent.asset_id == sw.id)} == {"queued"}
    log = db.query(AuditLog).filter(AuditLog.action == "group_run.start", AuditLog.target_id == run.id).one()
    assert "by netadmin, ops from 10.20.0.9, 10.20.0.10" in log.detail

    _drain(db)
    assert calls == ["10.61.1.1"]
    commits = []
    real_commit = db.commit
    monkeypatch.setattr(db, "commit", lambda: commits.append(1) or real_commit())
    assert C.process(db)["finished"] == 2
    assert commits                      # the outcome is saved even when nothing else happens in the pass
    events = db.query(ConfigChangeEvent).filter(ConfigChangeEvent.asset_id == sw.id).all()
    backup = db.get(DeviceBackup, events[0].backup_id)
    assert {e.status for e in events} == {"done"} and backup.source == "on_change"
    assert backup.change_origin == "external" and backup.changed is True

    listed = {b.id: b for b in list_backups(asset_id=sw.id, source=None, limit=50, offset=0, current_user=admin, db=db)}
    assert (listed[backup.id].reported_by, listed[backup.id].reported_from) == ("netadmin, ops", "10.20.0.9, 10.20.0.10")
    problems = alert_events._config_changed_external(db, {}, datetime.utcnow(), datetime.utcnow() - timedelta(minutes=5))
    p = next(p for p in problems if p.key == f"backup:{backup.id}")
    assert "changed by netadmin, ops from 10.20.0.9, 10.20.0.10" in p.detail

    timeline = overview360.build(db, sw, admin)["timeline"]
    change = next(e for e in timeline if e["kind"] == "change")
    assert change["link"] == f"/backup?asset={sw.id}&compare={backup.id}"

    # another change within a few minutes waits for the gap; then it is backed up again
    _event(db, sw, ago=70)
    assert C.process(db)["started"] == 0
    later = datetime.utcnow() + timedelta(seconds=C.MIN_GAP_SECONDS + 5)
    assert C.process(db, now=later)["started"] == 1


def test_a_device_still_being_changed_is_not_backed_up_yet(db, admin):
    sw = _asset(db, "10.61.2.1")
    _schedule(db, admin, [sw])
    _event(db, sw, ago=10)
    assert C.process(db)["started"] == 0
    assert db.query(ConfigChangeEvent).filter(ConfigChangeEvent.asset_id == sw.id).one().status == "pending"


def test_without_a_scheduled_backup_an_alert_says_so(db, admin):
    sw = _asset(db, "10.61.3.1")
    _schedule(db, admin, [sw], enabled=False)                  # a paused schedule does not count
    _event(db, sw, by="intruder", source="10.66.0.1")
    assert C.process(db)["no_schedule"] == 1
    problems = alert_events._config_reported(db, {}, datetime.utcnow(), datetime.utcnow() - timedelta(minutes=5))
    p = next(p for p in problems if p.asset_id == sw.id)
    assert p.title == "Configuration change reported, no backup taken"
    assert p.detail == "Changed by intruder from 10.66.0.1; no scheduled backup covers this device"
    assert "backup.config_reported" in alert_events.EVENTS


def test_turned_off(db, admin):
    sw = _asset(db, "10.61.4.1")
    _schedule(db, admin, [sw])
    _event(db, sw)
    assert C.process(db, backup_on_change=False)["off"] == 1
    assert db.query(ConfigChangeEvent).filter(ConfigChangeEvent.asset_id == sw.id).one().status == "off"


def test_old_events_are_removed(db, admin):
    sw = _asset(db, "10.61.5.1")
    old = _event(db, sw, ago=400 * 86400)
    old.status = "done"
    keep = _event(db, sw, ago=400 * 86400)                     # still waiting: kept
    db.flush()
    old_id, keep_id = old.id, keep.id
    out = retention.prune(db)
    assert out["change_events"] >= 1
    assert db.get(ConfigChangeEvent, old_id) is None and db.get(ConfigChangeEvent, keep_id) is not None
