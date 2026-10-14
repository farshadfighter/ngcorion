"""
Syslog intake (app/modules/syslog): parsing, the registered-assets-only rule, rate and size limits,
storage, retention, the real UDP/TCP listener on a local port, the API and the alerts.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import asyncio
import socket
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.security_audit_log import AuditLog
from app.models.syslog import SyslogMessage, SyslogSource, SyslogStatus
from app.modules.alerts import events as alert_events
from app.modules.syslog import intake as I
from app.modules.syslog import listener as L
from app.modules.syslog import retention
from app.modules.syslog import router as SR
from app.modules.syslog import settings as S
from app.modules.syslog.parser import MAX_MESSAGE, parse

REQ = SimpleNamespace(client=SimpleNamespace(host="10.9.9.9"), headers={})
NOW = datetime(2026, 10, 13, 12, 0, 0)


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


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def admin(db):
    u = User(username=f"sl_admin_{_n()}", hashed_password="x", role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db, ip):
    t = AssetType(type_name=f"Router {_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"rt-{_n()}", asset_type_id=t.id, ip_address=ip)
    db.add(a)
    db.flush()
    return a


def _msg(db, asset, severity=5, text="hello", when=None, app="app"):
    m = SyslogMessage(asset_id=asset.id, received_at=when or datetime.utcnow(), source_ip=asset.ip_address,
                      protocol="udp", facility=1, severity=severity, app_name=app, message=text)
    db.add(m)
    db.flush()
    return m


# ── parsing ─────────────────────────────────────────────────────────────────

def test_parses_the_formats_devices_send():
    p = parse(b'<34>1 2026-10-13T10:00:00.123+03:30 web01 sshd 1234 ID47 [x@1 a="b\\]c"] \xef\xbb\xbfFailed password',
              NOW)
    assert (p.facility, p.severity, p.hostname, p.app_name, p.message) == (4, 2, "web01", "sshd", "Failed password")
    assert p.device_time == datetime(2026, 10, 13, 6, 30, 0, 123000)

    p = parse(b"<189>45: *Oct 13 10:00:00.123: %SYS-5-CONFIG_I: Configured from console by admin", NOW)
    assert (p.severity, p.app_name, p.message) == (5, "%SYS-5-CONFIG_I", "Configured from console by admin")
    p = parse(b"<187>46: core-sw: *Oct 13 10:00:01 UTC: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", NOW)
    assert (p.severity, p.hostname, p.app_name) == (3, "core-sw", "%LINK-3-UPDOWN")

    p = parse(b"<86>Oct 13 10:01:02 lnx-web-01 sudo[999]: auditor : COMMAND=/bin/cat", NOW)
    assert (p.hostname, p.app_name, p.message) == ("lnx-web-01", "sudo", "auditor : COMMAND=/bin/cat")
    assert p.device_time == datetime(2026, 10, 13, 10, 1, 2)

    p = parse(b'<185>date=2026-10-13 time=10:20:30 devname="FGT-HQ" devid="FG100" logid="0100032002" type="event" '
              b'subtype="system" level="alert" logdesc="Admin login failed" user="admin" status="failed" '
              b'msg="Administrator admin login failed"', NOW)
    assert (p.hostname, p.app_name, p.device_time) == ("FGT-HQ", "Admin login failed", datetime(2026, 10, 13, 10, 20, 30))
    assert p.message == 'Administrator admin login failed · devid="FG100" logid="0100032002" user="admin" status="failed"'
    p = parse(b'<189>date=2026-10-13 time=10:20:30 devname="FGT-HQ" type="event" subtype="system"', NOW)
    assert (p.app_name, p.message) == ("event/system", 'date=2026-10-13 time=10:20:30 devname="FGT-HQ" type="event" subtype="system"')

    # Cisco NX-OS puts the year first, with or without ": " before it; it is not RFC 5424
    p = parse(b"<189>2026 Oct 13 10:00:01 nx1 %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by admin on 10.1.1.5@pts/0",
              NOW)
    assert (p.hostname, p.app_name, p.device_time) == ("nx1", "%VSHD-5-VSHD_SYSLOG_CONFIG_I", datetime(2026, 10, 13, 10, 0, 1))
    assert p.message == "Configured from vty by admin on 10.1.1.5@pts/0"
    p = parse(b"<189>: 2026 Oct 13 10:00:01.250 UTC: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down", NOW)
    assert (p.app_name, p.device_time, p.message) == ("%ETHPORT-5-IF_DOWN_LINK_FAILURE", datetime(2026, 10, 13, 10, 0, 1),
                                                      "Interface Ethernet1/1 is down")
    # a relay's header in front of the device's own sequence number and time, or before the mnemonic alone
    p = parse(b"<189>Oct 13 10:00:02 core-sw-01 123: Oct 13 10:00:01.123 UTC: %SYS-5-CONFIG_I: Configured from console by admin",
              NOW)
    assert (p.hostname, p.app_name, p.device_time, p.message) == (
        "core-sw-01", "%SYS-5-CONFIG_I", datetime(2026, 10, 13, 10, 0, 1), "Configured from console by admin")
    p = parse(b"<189>Oct 13 10:00:02 sw1 77: %SYS-5-CONFIG_I: Configured from console by admin", NOW)
    assert (p.hostname, p.app_name) == ("sw1", "%SYS-5-CONFIG_I")
    # RFC 5424 without a time still parses
    p = parse(b"<165>1 - host1 app - - - no time", NOW)
    assert (p.device_time, p.hostname, p.app_name, p.message) == (None, "host1", "app", "no time")

    # a BSD time without a year in the future is last year's
    assert parse(b"<14>Dec 31 23:59:59 host app: x", NOW).device_time.year == 2025


def test_bad_input_is_kept_safely():
    p = parse(b"no priority at all\r\n", NOW)
    assert (p.facility, p.severity, p.message) == (None, 5, "no priority at all")
    assert parse(b"<999>x", NOW).message == "<999>x"
    assert parse(b"<30>\x00\x01ctrl\x1bchars\xff", NOW).message == "ctrlchars�"
    assert len(parse(b"<13>" + b"A" * 50000, NOW).message) == MAX_MESSAGE
    assert parse(b"<13>", NOW).message == "(empty)"


def test_addresses_are_normalized():
    assert I.normalize_ip(" 10.0.0.5 ") == "10.0.0.5"
    assert I.normalize_ip("::ffff:10.0.0.5") == "10.0.0.5"
    assert I.normalize_ip("not-an-ip") is None and I.normalize_ip(None) is None


# ── intake ──────────────────────────────────────────────────────────────────

def test_only_registered_assets_are_stored(db):
    a = _asset(db, "10.77.0.1")
    intake = I.Intake()
    intake.load_assets(db)
    assert intake.accept(b"<11>Oct 13 10:00:00 rt app: disk failed", "10.77.0.1", "udp")
    assert not intake.accept(b"<11>spoofed", "10.77.9.9", "udp")
    assert not intake.accept(b"<11>again", "10.77.9.9", "udp")
    assert intake.drain(db) == 1
    m = db.query(SyslogMessage).filter(SyslogMessage.asset_id == a.id).one()
    assert (m.severity, m.app_name, m.message, m.protocol) == (3, "app", "disk failed", "udp")
    known = db.get(SyslogSource, "10.77.0.1")
    unknown = db.get(SyslogSource, "10.77.9.9")
    assert (known.asset_id, known.received, known.dropped, known.last_hostname) == (a.id, 1, 0, "rt")
    assert (unknown.asset_id, unknown.received, unknown.dropped) == (None, 0, 2)

    # counters add up across batches
    intake.accept(b"<14>two", "10.77.0.1", "tcp")
    intake.drain(db)
    db.refresh(known)
    assert known.received == 2


def test_rate_severity_and_queue_limits(db, monkeypatch):
    _asset(db, "10.77.0.2")
    monkeypatch.setattr(I, "BURST", 3)
    monkeypatch.setattr(I, "RATE_PER_SECOND", 0.001)
    intake = I.Intake(store_max_severity=4)
    intake.load_assets(db)
    taken = [intake.accept(b"<11>x", "10.77.0.2", "udp") for _ in range(5)]
    assert taken == [True, True, True, False, False]

    intake = I.Intake(store_max_severity=4)
    intake.load_assets(db)
    assert not intake.accept(b"<14>info is below the level", "10.77.0.2", "udp")
    monkeypatch.setattr(I, "QUEUE_MAX", 1)
    assert intake.accept(b"<12>warning", "10.77.0.2", "udp")
    assert not intake.accept(b"<12>queue full", "10.77.0.2", "udp")
    assert intake.queue_dropped == 1


def test_a_failed_write_keeps_the_messages(db, monkeypatch):
    _asset(db, "10.77.0.3")
    intake = I.Intake()
    intake.load_assets(db)
    intake.accept(b"<13>keep me", "10.77.0.3", "udp")

    class Broken:
        def execute(self, *a, **k):
            raise RuntimeError("database away")

        def rollback(self):
            pass

    with pytest.raises(RuntimeError):
        intake.drain(Broken())
    assert len(intake.queue) == 1
    assert intake.drain(db) == 1


# ── retention ───────────────────────────────────────────────────────────────

def test_retention_by_age_size_and_unknown_addresses(db, admin, monkeypatch):
    a = _asset(db, "10.77.0.4")
    S.save_settings(db, {"retention_days": 7}, admin.id)
    now = datetime.utcnow()
    old = _msg(db, a, when=now - timedelta(days=8))
    fresh = [_msg(db, a, when=now - timedelta(hours=i)).id for i in range(4)]
    old_id = old.id
    db.add(SyslogSource(source_ip="10.77.99.1", asset_id=None, first_seen=now - timedelta(days=40),
                        last_seen=now - timedelta(days=31), dropped=5))
    db.add(SyslogSource(source_ip="10.77.99.2", asset_id=None, first_seen=now, last_seen=now, dropped=1))
    db.flush()
    out = retention.prune(db, now)
    assert out["by_age"] >= 1 and out["unknown_sources"] >= 1
    assert db.get(SyslogMessage, old_id) is None
    assert db.get(SyslogSource, "10.77.99.1") is None and db.get(SyslogSource, "10.77.99.2") is not None

    # over the storage budget: the oldest go first
    monkeypatch.setattr(retention, "table_bytes", lambda _db: 10 * 1024 ** 4)
    monkeypatch.setattr(retention, "BATCH", 2)
    monkeypatch.setattr(retention, "MAX_BATCHES", 1)
    out = retention.prune(db, now)
    assert out["by_size"] == 2
    # the two lowest ids (the first written) went
    left = {m.id for m in db.query(SyslogMessage).filter(SyslogMessage.asset_id == a.id)}
    assert left == set(fresh[2:])


def test_settings_are_clamped_and_off_by_default(db, admin):
    db.query(SyslogStatus).delete()
    from app.models.system_config import SystemConfigSetting
    db.query(SystemConfigSetting).filter(SystemConfigSetting.section == S.SECTION).delete()
    assert S.get_settings(db)["enabled"] is False
    saved = S.save_settings(db, {"enabled": True, "retention_days": 9999, "store_max_severity": -3}, admin.id)
    assert (saved["enabled"], saved["retention_days"], saved["store_max_severity"]) == (True, 365, 0)


# ── the real listener ───────────────────────────────────────────────────────

def _free_port() -> int:
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            t.bind(("127.0.0.1", 0))
            port = t.getsockname()[1]
            try:
                u.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port")


def test_listener_receives_udp_and_tcp_from_assets_only(db, admin, monkeypatch):
    port = _free_port()
    S.save_settings(db, {"enabled": True, "udp": True, "tcp": True, "store_max_severity": 7}, admin.id)
    monkeypatch.setattr(L, "SessionLocal", lambda: _Shared(db))
    monkeypatch.setattr(L, "SETTINGS_EVERY", 0.2)
    monkeypatch.setattr(L, "TICK", 0.05)

    async def scenario():
        lst = L.SyslogListener(port=port, bind="127.0.0.1")
        lst.start()
        for _ in range(50):
            if lst.listening_udp and lst.listening_tcp:
                break
            await asyncio.sleep(0.05)
        assert lst.listening_udp and lst.listening_tcp

        # 127.0.0.1 is not an asset yet: UDP dropped, TCP closed at once
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(b"<11>not an asset yet", ("127.0.0.1", port))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(r.read(), timeout=2) == b""
        w.close()

        a = _asset(db, "127.0.0.1")
        lst.intake.assets_loaded_at = 0
        for _ in range(60):
            if lst.intake.known("127.0.0.1"):
                break
            await asyncio.sleep(0.05)
        assert lst.intake.known("127.0.0.1") == a.id

        u.sendto(b"<11>Oct 13 10:00:00 lo app: over udp", ("127.0.0.1", port))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"<12>Oct 13 10:00:01 lo app: line one\n<13>line two\n")
        frame = b"<14>1 2026-10-13T10:00:02Z lo app - - - counted"
        w.write(str(len(frame)).encode() + b" " + frame)
        await w.drain()
        for _ in range(60):
            if db.query(SyslogMessage).filter(SyslogMessage.asset_id == a.id).count() >= 4:
                break
            await asyncio.sleep(0.05)
        w.close()
        u.close()

        # turning it off closes the sockets
        S.save_settings(db, {"enabled": False}, admin.id)
        for _ in range(50):
            if not lst.listening_udp and not lst.listening_tcp:
                break
            await asyncio.sleep(0.05)
        assert not lst.listening_udp and not lst.listening_tcp
        await lst.stop()
        return a

    a = asyncio.run(scenario())
    got = {(m.protocol, m.message) for m in db.query(SyslogMessage).filter(SyslogMessage.asset_id == a.id)}
    assert got == {("udp", "over udp"), ("tcp", "line one"), ("tcp", "line two"), ("tcp", "counted")}
    src = db.get(SyslogSource, "127.0.0.1")
    assert src.asset_id == a.id and src.received == 4 and src.dropped >= 2
    st = db.get(SyslogStatus, 1)
    assert st.port == port and st.updated_at is not None


def test_listener_reports_a_port_it_cannot_open(db, admin, monkeypatch):
    S.save_settings(db, {"enabled": True, "udp": False, "tcp": True}, admin.id)
    monkeypatch.setattr(L, "SessionLocal", lambda: _Shared(db))
    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    port = busy.getsockname()[1]

    async def scenario():
        lst = L.SyslogListener(port=port, bind="127.0.0.1")
        lst.start()
        await asyncio.sleep(0.3)
        err = lst.error
        await lst.stop()
        return err

    try:
        err = asyncio.run(scenario())
    finally:
        busy.close()
    assert err and f"TCP port {port}" in err
    st = SR.listener_status(db)
    assert st.enabled and not st.listening and st.error
    problems = alert_events._syslog_not_listening(db, {}, datetime.utcnow(), datetime.utcnow())
    assert [p.key for p in problems] == ["syslog:listener"]


# ── API ─────────────────────────────────────────────────────────────────────

def test_messages_filters_paging_and_export(db, admin):
    a, b = _asset(db, "10.77.1.1"), _asset(db, "10.77.1.2")
    now = datetime.utcnow()
    _msg(db, a, 2, "link down 100%", now - timedelta(minutes=5))
    _msg(db, a, 6, "user logged in", now - timedelta(minutes=4))
    _msg(db, a, 3, "=cmd|' /C calc'!A0", now - timedelta(minutes=3))
    _msg(db, b, 1, "fan failure", now - timedelta(minutes=2))

    page = SR.list_messages(asset_id=a.id, severity=3, q=None, since=None, until=None, before_id=None, limit=1,
                            current_user=admin, db=db)
    assert [m.message for m in page.items] == ["=cmd|' /C calc'!A0"] and page.next_before_id
    page2 = SR.list_messages(asset_id=a.id, severity=3, q=None, since=None, until=None,
                             before_id=page.next_before_id, limit=5, current_user=admin, db=db)
    assert [m.message for m in page2.items] == ["link down 100%"] and page2.next_before_id is None
    # "%" is matched literally
    found = SR.list_messages(asset_id=None, severity=None, q="100%", since=now - timedelta(hours=1), until=None,
                             before_id=None, limit=50, current_user=admin, db=db)
    assert [m.message for m in found.items] == ["link down 100%"]
    assert SR.list_messages(asset_id=None, severity=None, q="0_", since=None, until=None, before_id=None, limit=50,
                            current_user=admin, db=db).items == []

    resp = SR.export_messages(REQ, asset_id=a.id, severity=None, q=None, since=None, until=None,
                              current_user=admin, db=db)
    body = resp.body.decode("utf-8")
    assert "'=cmd" in body and "user logged in" in body and "fan failure" not in body
    assert db.query(AuditLog).filter(AuditLog.action == "syslog.export", AuditLog.user_id == admin.id).count() == 1


def test_overview_and_settings(db, admin):
    a = _asset(db, "10.77.2.1")
    _msg(db, a, 2)
    _msg(db, a, 6)
    now = datetime.utcnow()
    db.add(SyslogSource(source_ip="10.77.2.1", asset_id=a.id, first_seen=now, last_seen=now, received=2))
    db.add(SyslogSource(source_ip="10.77.2.99", asset_id=None, first_seen=now, last_seen=now, dropped=7))
    db.flush()
    ov = SR.overview(current_user=admin, db=db)
    assert ov.by_severity_24h[2] >= 1 and ov.by_severity_24h[6] >= 1
    mine = [s for s in ov.assets if s.asset_id == a.id][0]
    assert mine.last_24h == 2 and mine.received == 2
    assert any(u.source_ip == "10.77.2.99" and u.dropped == 7 for u in ov.unknown)

    body = SR.SyslogSettings(enabled=True, udp=False, tcp=False, retention_days=30, storage_budget_gb=5,
                             store_max_severity=7)
    with pytest.raises(HTTPException) as e:
        SR.save_settings(body, REQ, current_user=admin, db=db)
    assert e.value.status_code == 400
    body.tcp = True
    saved = SR.save_settings(body, REQ, current_user=admin, db=db)
    assert saved["enabled"] and saved["tcp"] and not saved["udp"]
    details = [r.detail for r in db.query(AuditLog).filter(AuditLog.action == "syslog.settings",
                                                           AuditLog.user_id == admin.id)]
    assert "Syslog intake turned on" in details
    assert any(d.startswith("Syslog intake settings: TCP, kept 30 days") for d in details)


def test_settings_change_is_for_administrators_only():
    from fastapi.routing import APIRoute
    route = [r for r in SR.router.routes if isinstance(r, APIRoute) and r.path == "/api/syslog/settings"
             and "PUT" in r.methods][0]
    from app.core.dependencies import require_admin
    assert any(d.call is require_admin for d in route.dependant.dependencies)


# ── alerts ──────────────────────────────────────────────────────────────────

def test_alerts(db, admin):
    a, b = _asset(db, "10.77.3.1"), _asset(db, "10.77.3.2")
    now = datetime.utcnow()
    _msg(db, a, 2, "first")
    last = _msg(db, a, 0, "kernel panic", app="kernel")
    _msg(db, a, 5, "notice only")
    _msg(db, b, 4, "warning only")
    severe = alert_events._syslog_severe(db, {"severity": 2}, now, now - timedelta(minutes=5))
    mine = [p for p in severe if p.asset_id == a.id]
    assert len(mine) == 1 and mine[0].key == f"syslog:{a.id}:{last.id}"
    assert mine[0].detail == "2 message(s), latest: kernel: kernel panic"
    assert not [p for p in severe if p.asset_id == b.id]

    S.save_settings(db, {"enabled": True}, admin.id)
    db.add(SyslogSource(source_ip="10.77.3.1", asset_id=a.id, first_seen=now - timedelta(days=3),
                        last_seen=now - timedelta(hours=30), received=10))
    db.add(SyslogSource(source_ip="10.77.3.2", asset_id=b.id, first_seen=now, last_seen=now, received=1))
    db.add(SyslogSource(source_ip="10.77.3.200", asset_id=None, first_seen=now, last_seen=now, dropped=3))
    db.flush()
    silent = alert_events._syslog_silent(db, {"hours": 24}, now, now)
    assert {p.asset_id for p in silent if p.asset_id in (a.id, b.id)} == {a.id}
    unknown = alert_events._syslog_unknown(db, {}, now, now)
    assert any(p.key == "source:10.77.3.200" for p in unknown)
    S.save_settings(db, {"enabled": False}, admin.id)
    assert alert_events._syslog_silent(db, {"hours": 24}, now, now) == []
    assert alert_events._syslog_not_listening(db, {}, now, now) == []
