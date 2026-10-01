"""
Alerts and notifications: the engine (raise, resolve, hold), dispatch
(grouping, reminders, quiet hours, resolved notices), the send queue with
retries, the channels' wire formats, and the API (visibility, lifecycle,
rule validation, webhooks).

Everything runs inside a rolled-back transaction. The engine evaluates every
enabled rule of an event type, so assertions look only at this test's rules.
"""
import hashlib
import hmac
import importlib
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.credential_crypto import PURPOSE_NOTIFICATIONS, decrypt
from app.core.database import engine as db_engine
from app.models import Asset, User, UserPermission, UserRole
from app.models.risk import AssetRiskProfile, RiskZone
from app.models.asset_types import AssetType
from app.models.backup_restore import BackupRestore
from app.models.noc import AssetSnmpInterface, AssetSnmpStatus
from app.models.noc_metrics import AssetMetricSample
from app.models.notification import Alert, NotificationDelivery, NotificationRule, NotificationWebhook
from app.models.topology import TopologyLink
from app.models.user_permission import ModuleEnum
from app.modules.alerts import channels as ch
from app.modules.alerts import engine
from app.modules.alerts.events import EVENTS, normalize_interface

api = importlib.import_module("app.modules.alerts.router")

NOW = datetime(2026, 10, 1, 10, 0, 0)


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


@pytest.fixture(autouse=True)
def _reset_engine_state():
    engine._last_checked.clear()
    engine._held_since.clear()
    yield
    engine._last_checked.clear()
    engine._held_since.clear()


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


def _user(db, role=UserRole.ADMIN, phone=None, perms=()):
    n = _n()
    u = User(username=f"alert_user_{n}", email=f"alert{n}@example.com", hashed_password="x", role=role,
             phone=phone, is_active=True)
    db.add(u)
    db.flush()
    for module in perms:
        db.add(UserPermission(user_id=u.id, module=module, can_read=True, can_write=False, can_delete=False))
    db.flush()
    return u


def _asset(db, name="RTR-Test", type_name="Router", zone=None):
    t = AssetType(type_name=f"{type_name} {_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"{name}-{_n()}", asset_type_id=t.id, ip_address=f"10.88.{_n() % 250}.{_n() % 250}")
    db.add(a)
    db.flush()
    if zone is not None:
        db.add(AssetRiskProfile(asset_id=a.id, criticality_level="medium", criticality_score=50, zone_id=zone.id))
        db.flush()
    return a


def _zone(db, name):
    z = RiskZone(name=f"{name} {_n()}", score=50)
    db.add(z)
    db.flush()
    return z


def _rule(db, event_type, **kw):
    event = EVENTS[event_type]
    values = dict(event_type=event_type, name=f"{event.name} test {_n()}", enabled=True, severity=event.severity,
                  params={p.key: p.default for p in event.params}, asset_scope="all", asset_filter={},
                  recipients={"roles": [], "user_ids": [], "emails": [], "phones": [], "owner": False},
                  channels=[], repeat_minutes=0, notify_resolved=True, group_minutes=0, builtin=False,
                  created_at=NOW - timedelta(days=1))
    values.update(kw)
    r = NotificationRule(**values)
    db.add(r)
    db.flush()
    return r


def _unreachable(db, asset, failures=3):
    s = AssetSnmpStatus(asset_id=asset.id, reachable=failures == 0, consecutive_poll_failures=failures,
                        last_polled_at=NOW, error_message="timeout" if failures else None)
    db.add(s)
    db.flush()
    return s


def _alerts(db, rule):
    return db.query(Alert).filter(Alert.rule_id == rule.id).order_by(Alert.id).all()


def _deliveries(db, rule):
    return db.query(NotificationDelivery).filter(NotificationDelivery.rule_id == rule.id).order_by(
        NotificationDelivery.id).all()


# ---------------------------------------------------------------------------
# Rules seeding
# ---------------------------------------------------------------------------

def test_default_rules_seeded_once(db):
    engine.ensure_default_rules(db)
    engine.ensure_default_rules(db)
    builtins = db.query(NotificationRule).filter(NotificationRule.builtin.is_(True)).all()
    codes = [r.event_type for r in builtins]
    assert sorted(codes) == sorted(EVENTS)
    assert len(codes) == len(set(codes))
    unreachable = next(r for r in builtins if r.event_type == "noc.device_unreachable")
    assert unreachable.severity == "critical" and "sms" in unreachable.channels
    assert unreachable.quiet_start == "22:00"
    assert next(r for r in builtins if r.event_type == "audit.compliance_drop").enabled is False


# ---------------------------------------------------------------------------
# Engine: state alerts
# ---------------------------------------------------------------------------

def test_state_alert_raises_updates_and_resolves(db):
    rule = _rule(db, "noc.device_unreachable", channels=["email"])
    asset = _asset(db)
    status = _unreachable(db, asset, failures=2)

    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    assert _alerts(db, rule) == []                      # below the 3-poll threshold

    status.consecutive_poll_failures = 4
    db.flush()
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    [alert] = _alerts(db, rule)
    assert alert.status == "active" and alert.severity == "critical" and alert.asset_id == asset.id
    assert alert.source_label.startswith(asset.asset_name) and alert.link == f"/noc/hosts/{asset.id}"
    assert "4 polls" in alert.detail
    assert rule.last_fired_at == NOW

    later = NOW + timedelta(minutes=1)
    engine.evaluate(db, later, force=True, only=["noc.device_unreachable"])
    [same] = _alerts(db, rule)
    assert same.id == alert.id and same.last_seen_at == later

    alert.notified_at = NOW                              # it was sent, so recovery is announced
    status.consecutive_poll_failures = 0
    db.flush()
    engine.evaluate(db, later, force=True, only=["noc.device_unreachable"])
    db.refresh(alert)
    assert alert.status == "resolved" and alert.resolved_by is None
    assert alert.resolved_notice_pending is True


def test_resolve_without_notice_when_never_sent(db):
    rule = _rule(db, "noc.device_unreachable", channels=["email"])
    status = _unreachable(db, _asset(db))
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    status.consecutive_poll_failures = 0
    db.flush()
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    [alert] = _alerts(db, rule)
    assert alert.status == "resolved" and alert.resolved_notice_pending is False


def test_rule_threshold_param_is_used(db):
    rule = _rule(db, "noc.device_unreachable", params={"polls": 6})
    _unreachable(db, _asset(db), failures=5)
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    assert _alerts(db, rule) == []


def test_asset_scope_matching_and_specific(db):
    core_zone = _zone(db, "Core")
    core = _asset(db, "core", zone=core_zone)
    edge = _asset(db, "edge", zone=_zone(db, "DMZ"))
    _unreachable(db, core)
    _unreachable(db, edge)
    by_zone = _rule(db, "noc.device_unreachable", asset_scope="matching", asset_filter={"zone_ids": [core_zone.id]})
    by_type = _rule(db, "noc.device_unreachable", asset_scope="matching",
                    asset_filter={"type_ids": [edge.asset_type_id]})
    specific = _rule(db, "noc.device_unreachable", asset_scope="specific", asset_filter={"asset_ids": [edge.id]})
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    assert [a.asset_id for a in _alerts(db, by_zone)] == [core.id]
    assert [a.asset_id for a in _alerts(db, by_type)] == [edge.id]
    assert [a.asset_id for a in _alerts(db, specific)] == [edge.id]


def test_disabled_rule_is_not_evaluated(db):
    rule = _rule(db, "noc.device_unreachable", enabled=False)
    _unreachable(db, _asset(db))
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    assert _alerts(db, rule) == []


def test_checks_respect_their_interval(db):
    rule = _rule(db, "noc.device_unreachable")
    status = _unreachable(db, _asset(db), failures=0)
    engine.evaluate(db, NOW, only=["noc.device_unreachable"])
    status.consecutive_poll_failures = 3
    db.flush()
    engine.evaluate(db, NOW, only=["noc.device_unreachable"])       # checked moments ago: not due
    assert _alerts(db, rule) == []
    engine.evaluate(db, NOW, force=True, only=["noc.device_unreachable"])
    assert len(_alerts(db, rule)) == 1


def test_held_problem_raises_only_after_it_lasts(db):
    rule = _rule(db, "system.task_stopped", params={"minutes": 5})
    with patch("app.modules.system_health._lock_held", lambda _db, name: name != "noc-poller"):
        engine.evaluate(db, NOW, force=True, only=["system.task_stopped"])
        assert _alerts(db, rule) == []
        engine.evaluate(db, NOW + timedelta(minutes=4), force=True, only=["system.task_stopped"])
        assert _alerts(db, rule) == []
        engine.evaluate(db, NOW + timedelta(minutes=5), force=True, only=["system.task_stopped"])
    [alert] = _alerts(db, rule)
    assert "NOC poller" in alert.detail


def test_failing_evaluator_does_not_stop_others(db):
    bad = _rule(db, "system.disk_low")
    good = _rule(db, "noc.device_unreachable")
    _unreachable(db, _asset(db))
    with patch.object(EVENTS["system.disk_low"], "evaluate", side_effect=RuntimeError("boom")):
        engine.evaluate(db, NOW, force=True, only=["system.disk_low", "noc.device_unreachable"])
    assert _alerts(db, bad) == [] and len(_alerts(db, good)) == 1


# ---------------------------------------------------------------------------
# Engine: event alerts
# ---------------------------------------------------------------------------

def _restore(db, asset, status, finished, requested_by=None):
    r = BackupRestore(asset_id=asset.id, asset_name=asset.asset_name, device_ip=asset.ip_address,
                      device_type="cisco", status=status, reason="test", error="Verification found 2 lines",
                      requested_by=requested_by, created_at=finished, finished_at=finished, events=[])
    db.add(r)
    db.flush()
    return r


def test_event_alert_raised_once_and_stays_closed(db):
    owner = _user(db)
    rule = _rule(db, "backup.restore_failed")
    asset = _asset(db)
    restore = _restore(db, asset, "reverted", NOW - timedelta(minutes=5), owner.id)
    _restore(db, asset, "succeeded", NOW - timedelta(minutes=4))
    _restore(db, asset, "failed", NOW - timedelta(days=3))          # older than the rule

    engine.evaluate(db, NOW, force=True, only=["backup.restore_failed"])
    [alert] = _alerts(db, rule)
    assert alert.title == "Restore reverted automatically" and alert.owner_user_id == owner.id
    assert alert.link == f"/backup/restores?restore={restore.id}"

    engine.evaluate(db, NOW, force=True, only=["backup.restore_failed"])
    assert len(_alerts(db, rule)) == 1                              # not raised twice

    engine.resolve(db, alert, owner.id)
    db.flush()
    engine.evaluate(db, NOW, force=True, only=["backup.restore_failed"])
    assert len(_alerts(db, rule)) == 1 and _alerts(db, rule)[0].status == "resolved"


# ---------------------------------------------------------------------------
# NOC interface checks
# ---------------------------------------------------------------------------

def test_normalize_interface():
    assert normalize_interface("GigabitEthernet0/1") == normalize_interface("Gi0/1") == "gi0/1"
    assert normalize_interface("TenGigabitEthernet1/0/1") == "te1/0/1"
    assert normalize_interface(" port-channel 1") == "po1"


def _iface(db, asset, name, admin="up", oper="down", speed=1_000_000_000):
    i = AssetSnmpInterface(asset_id=asset.id, if_index=_n(), if_name=name, if_descr=name, if_speed=speed,
                           if_admin_status=admin, if_oper_status=oper, last_polled_at=NOW)
    db.add(i)
    db.flush()
    return i


def test_interface_down_only_for_linked_ports(db):
    sw = _asset(db, "sw")
    peer = _asset(db, "peer")
    _unreachable(db, sw, failures=0)
    uplink = _iface(db, sw, "GigabitEthernet0/24")
    _iface(db, sw, "GigabitEthernet0/5")                            # unused access port
    _iface(db, sw, "GigabitEthernet0/23", admin="down")             # shut on purpose
    db.add(TopologyLink(source_asset_id=sw.id, destination_asset_id=peer.id, source_interface="Gi0/24",
                        destination_interface="Gi1/1", link_type="ethernet", status="active"))
    db.flush()
    linked = _rule(db, "noc.interface_down")
    every = _rule(db, "noc.interface_down", params={"linked_only": 0})
    with patch("app.modules.alerts.events.datetime") as _dt:
        _dt.utcnow.return_value = NOW
        engine.evaluate(db, NOW, force=True, only=["noc.interface_down"])
    assert [a.fingerprint for a in _alerts(db, linked)] == [f"{linked.id}:if:{uplink.id}"]
    assert len(_alerts(db, every)) == 2


def test_interface_down_skipped_when_device_unreachable(db):
    sw = _asset(db, "sw")
    _unreachable(db, sw, failures=3)
    _iface(db, sw, "Gi0/1")
    rule = _rule(db, "noc.interface_down", params={"linked_only": 0})
    engine.evaluate(db, NOW, force=True, only=["noc.interface_down"])
    assert _alerts(db, rule) == []


def test_interface_utilization(db):
    sw = _asset(db, "sw")
    busy = _iface(db, sw, "Gi0/1", oper="up", speed=100_000_000)     # 100 Mb/s
    quiet = _iface(db, sw, "Gi0/2", oper="up", speed=100_000_000)
    start = NOW - timedelta(minutes=10)
    for minute in range(0, 11):
        at = start + timedelta(minutes=minute)
        # busy: 95 Mb/s in; quiet: 10 Mb/s out
        db.add(AssetMetricSample(asset_id=sw.id, interface_id=busy.id, metric_type="if_in_octets",
                                 value=minute * 60 * 95_000_000 / 8, sampled_at=at))
        db.add(AssetMetricSample(asset_id=sw.id, interface_id=quiet.id, metric_type="if_out_octets",
                                 value=minute * 60 * 10_000_000 / 8, sampled_at=at))
    db.flush()
    rule = _rule(db, "noc.interface_utilization")
    engine.evaluate(db, NOW + timedelta(seconds=1), force=True, only=["noc.interface_utilization"])
    [alert] = _alerts(db, rule)
    assert alert.fingerprint.endswith(f"util:{busy.id}") and "95% (in)" in alert.detail


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _raise(db, rule, asset=None, severity=None, at=NOW, key=None):
    a = Alert(rule_id=rule.id, event_type=rule.event_type, module=EVENTS[rule.event_type].module,
              severity=severity or rule.severity, fingerprint=f"{rule.id}:{key or _n()}", title="Device unreachable",
              detail="No answer", asset_id=asset.id if asset else None, source_label="RTR · 10.0.0.1",
              status="active", first_seen_at=at, last_seen_at=at)
    db.add(a)
    db.flush()
    return a


def test_dispatch_resolves_recipients_per_channel(db):
    admin = _user(db, UserRole.ADMIN, phone="+989121111111")
    manager = _user(db, UserRole.MANAGER, phone="09122222222")
    _user(db, UserRole.USER, phone="09123333333")                  # not addressed
    hook = NotificationWebhook(name="ops", url="https://hooks.example.com/x", secret_encrypted="x")
    db.add(hook)
    db.flush()
    rule = _rule(db, "noc.device_unreachable", severity="critical",
                 recipients={"roles": ["admin"], "user_ids": [manager.id], "emails": ["noc@example.com"],
                             "phones": ["09124444444"]},
                 channels=["email", "sms", "syslog", f"webhook:{hook.id}"])
    alert = _raise(db, rule)
    engine.dispatch(db, NOW)
    rows = _deliveries(db, rule)
    emails = {d.recipient for d in rows if d.channel == "email"}
    phones = {d.recipient for d in rows if d.channel == "sms"}
    assert {admin.email, manager.email, "noc@example.com"} <= emails
    assert {"+989121111111", "09122222222", "09124444444"} <= phones and "09123333333" not in phones
    assert [d.channel for d in rows].count("syslog") == 1 and [d.channel for d in rows].count("webhook") == 1
    assert all(d.kind == "raised" and d.alert_ids == [alert.id] for d in rows)
    assert rows[0].subject.startswith("[Critical] Device unreachable - RTR")
    db.refresh(alert)
    assert alert.notified_at == NOW


def test_dispatch_groups_bursts(db):
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["a@example.com"]}, channels=["email"],
                 group_minutes=5)
    _raise(db, rule)
    engine.dispatch(db, NOW)
    assert len(_deliveries(db, rule)) == 1

    _raise(db, rule, at=NOW + timedelta(minutes=1))
    _raise(db, rule, at=NOW + timedelta(minutes=2))
    engine.dispatch(db, NOW + timedelta(minutes=2))                 # inside the window: wait
    assert len(_deliveries(db, rule)) == 1
    engine.dispatch(db, NOW + timedelta(minutes=5))
    rows = _deliveries(db, rule)
    assert len(rows) == 2 and len(rows[1].alert_ids) == 2 and "2 alerts" in rows[1].subject


def test_reminders_until_acknowledged(db):
    user = _user(db)
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["a@example.com"]}, channels=["email"],
                 repeat_minutes=60)
    alert = _raise(db, rule)
    engine.dispatch(db, NOW)
    engine.dispatch(db, NOW + timedelta(minutes=30))
    assert [d.kind for d in _deliveries(db, rule)] == ["raised"]
    engine.dispatch(db, NOW + timedelta(minutes=61))
    assert [d.kind for d in _deliveries(db, rule)] == ["raised", "reminder"]
    assert _deliveries(db, rule)[1].subject.startswith("[Reminder]")
    engine.acknowledge(db, alert, user.id)
    db.flush()
    engine.dispatch(db, NOW + timedelta(minutes=200))
    assert [d.kind for d in _deliveries(db, rule)] == ["raised", "reminder"]


def test_resolved_notice_sent_once(db):
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["a@example.com"]}, channels=["email"])
    alert = _raise(db, rule)
    alert.status, alert.resolved_at, alert.notified_at = "resolved", NOW, NOW
    alert.resolved_notice_pending = True
    db.flush()
    engine.dispatch(db, NOW)
    engine.dispatch(db, NOW)
    rows = _deliveries(db, rule)
    assert [d.kind for d in rows] == ["resolved"] and rows[0].subject.startswith("[Resolved]")


def test_in_app_only_rule_marks_alerts_notified(db):
    rule = _rule(db, "noc.device_unreachable", channels=[])
    alert = _raise(db, rule)
    engine.dispatch(db, NOW)
    db.refresh(alert)
    assert alert.notified_at == NOW and _deliveries(db, rule) == []


@pytest.mark.parametrize("severity,expected", [("warning", "skipped"), ("critical", "pending")])
def test_sms_quiet_hours(db, severity, expected):
    rule = _rule(db, "noc.device_unreachable", severity=severity, recipients={"phones": ["09121234567"]},
                 channels=["sms"], quiet_start="22:00", quiet_end="07:00")
    _raise(db, rule, severity=severity)
    night = datetime(2026, 10, 1, 23, 30)
    with patch.object(ch, "local_timezone", return_value=None):
        engine.dispatch(db, night)
    [d] = _deliveries(db, rule)
    assert d.status == expected


def test_quiet_hours_window():
    rule = SimpleNamespace(quiet_start="22:00", quiet_end="07:00")
    assert engine._in_quiet_hours(rule, datetime(2026, 1, 1, 23, 0), None)
    assert engine._in_quiet_hours(rule, datetime(2026, 1, 1, 6, 59), None)
    assert not engine._in_quiet_hours(rule, datetime(2026, 1, 1, 7, 0), None)
    day = SimpleNamespace(quiet_start="12:00", quiet_end="13:00")
    assert engine._in_quiet_hours(day, datetime(2026, 1, 1, 12, 30), None)
    assert not engine._in_quiet_hours(SimpleNamespace(quiet_start=None, quiet_end=None),
                                      datetime(2026, 1, 1, 23, 0), None)


# ---------------------------------------------------------------------------
# Send queue
# ---------------------------------------------------------------------------

def test_send_retries_then_fails(db):
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["a@example.com"]}, channels=["email"])
    _raise(db, rule)
    engine.dispatch(db, NOW)
    [d] = _deliveries(db, rule)
    with patch.object(ch, "send_email", side_effect=ch.DeliveryError("SMTP error: refused")):
        engine.send_pending(db, NOW)
        db.refresh(d)
        assert d.status == "pending" and d.attempts == 1 and "refused" in d.error
        assert d.next_attempt_at > NOW
        engine.send_pending(db, d.next_attempt_at)
        engine.send_pending(db, db.get(NotificationDelivery, d.id).next_attempt_at)
    db.refresh(d)
    assert d.status == "failed" and d.attempts == 3


def test_send_success(db):
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["a@example.com"]}, channels=["email"])
    _raise(db, rule)
    engine.dispatch(db, NOW)
    sent = []
    with patch.object(ch, "send_email", lambda cfg, to, subj, body, html=None: sent.append((to, subj))):
        stats = engine.send_pending(db, NOW)
    assert stats["sent"] >= 1 and (["a@example.com"], _deliveries(db, rule)[0].subject) in sent
    assert _deliveries(db, rule)[0].status == "sent"


def test_webhook_delivery_records_errors(db):
    from app.core.credential_crypto import encrypt
    hook = NotificationWebhook(name="ops", url="https://hooks.example.com/x",
                               secret_encrypted=encrypt("s3cret", PURPOSE_NOTIFICATIONS))
    db.add(hook)
    db.flush()
    rule = _rule(db, "noc.device_unreachable", channels=[f"webhook:{hook.id}"])
    _raise(db, rule)
    engine.dispatch(db, NOW)
    with patch.object(ch, "send_webhook", side_effect=ch.DeliveryError("HTTP 502")):
        engine.send_pending(db, NOW)
    db.refresh(hook)
    assert hook.last_error == "HTTP 502"
    calls = []
    with patch.object(ch, "send_webhook", lambda url, secret, payload: calls.append((url, secret, payload))):
        engine.send_pending(db, NOW + timedelta(minutes=2))
    db.refresh(hook)
    assert hook.last_success_at is not None
    assert calls[0][1] == "s3cret" and calls[0][2]["kind"] == "raised" and calls[0][2]["alerts"][0]["title"]


# ---------------------------------------------------------------------------
# Channel formats
# ---------------------------------------------------------------------------

def test_cef_escaping():
    line = ch.cef_message({"event_type": "noc.device_unreachable", "title": "Down | now", "severity": "critical",
                           "detail": "a=b\nc\\d", "module": "noc", "alert_id": 7, "kind": "raised"})
    assert line.startswith("CEF:0|NGCorion|NGCorion|")
    assert "|noc.device_unreachable|Down \\| now|9|" in line
    assert "msg=a\\=b\\nc\\\\d" in line and "cs1=7" in line


def test_syslog_sends_rfc5424_with_cef():
    sent = {}

    class FakeSock:
        def __init__(self, *a):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            sent["data"], sent["addr"] = data, addr

    with patch("socket.socket", FakeSock):
        ch.send_syslog({"server_ip": "10.0.9.20", "port": 1514, "protocol": "UDP", "facility": "local0"},
                       {"severity": "critical", "title": "X", "event_type": "e"})
    assert sent["addr"] == ("10.0.9.20", 1514)
    assert sent["data"].startswith(b"<130>1 ")                       # local0 (16) * 8 + critical (2)
    assert b"CEF:0|NGCorion" in sent["data"]


def test_webhook_signature():
    body = b'{"a":1}'
    sig = ch.sign("secret", "1700000000", body)
    expected = hmac.new(b"secret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


@pytest.mark.parametrize("url,ok", [
    ("https://10.1.2.3/hook", True),
    ("http://127.0.0.1:8000/api", False),
    ("http://169.254.169.254/latest/meta-data", False),
    ("ftp://10.1.2.3/x", False),
    ("https://user:pw@10.1.2.3/x", False),
])
def test_webhook_url_policy(url, ok):
    if ok:
        assert ch.check_webhook_url(url) == url
    else:
        with pytest.raises(ValueError):
            ch.check_webhook_url(url)


def test_send_email_requires_configuration():
    with pytest.raises(ch.DeliveryError, match="not configured"):
        ch.send_email({}, ["a@example.com"], "s", "b")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def test_alerts_visible_by_module_permission(db):
    noc_rule = _rule(db, "noc.device_unreachable")
    cve_rule = _rule(db, "cve.kev_finding")
    noc_alert = _raise(db, noc_rule)
    cve_alert = Alert(rule_id=cve_rule.id, event_type="cve.kev_finding", module="cve", severity="critical",
                      fingerprint=f"{cve_rule.id}:x", title="KEV", status="active", first_seen_at=NOW, last_seen_at=NOW)
    db.add(cve_alert)
    db.flush()
    noc_only = _user(db, UserRole.USER, perms=[ModuleEnum.NOC])
    ids = {a["id"] for a in api.list_alerts(status="open", module=None, severity=None, search=None, offset=0,
                                            limit=200, current_user=noc_only, db=db)["items"]}
    assert noc_alert.id in ids and cve_alert.id not in ids
    with pytest.raises(HTTPException) as exc:
        api.acknowledge_alert(cve_alert.id, current_user=noc_only, db=db)
    assert exc.value.status_code == 404


def test_acknowledge_and_resolve_flow(db):
    user = _user(db)
    rule = _rule(db, "noc.device_unreachable")
    alert = _raise(db, rule)
    out = api.acknowledge_alert(alert.id, current_user=user, db=db)
    assert out["status"] == "acknowledged" and out["acknowledged_by"] == user.username
    with pytest.raises(HTTPException) as exc:
        api.acknowledge_alert(alert.id, current_user=user, db=db)
    assert exc.value.status_code == 409
    listed = api.list_alerts(status="acknowledged", module=None, severity=None, search=None, offset=0, limit=200,
                             current_user=user, db=db)
    assert alert.id in {a["id"] for a in listed["items"]}
    out = api.resolve_alert(alert.id, current_user=user, db=db)
    assert out["status"] == "resolved" and out["resolved_by"] == user.username and not out["auto_resolved"]


def test_list_orders_unacknowledged_and_critical_first(db):
    user = _user(db)
    rule = _rule(db, "noc.device_unreachable")
    warn = _raise(db, rule, severity="warning", at=NOW + timedelta(minutes=5))
    crit = _raise(db, rule, severity="critical", at=NOW)
    acked = _raise(db, rule, severity="critical", at=NOW + timedelta(minutes=9))
    engine.acknowledge(db, acked, user.id)
    db.flush()
    items = api.list_alerts(status="open", module="noc", severity=None, search=None, offset=0, limit=200,
                            current_user=user, db=db)["items"]
    order = [a["id"] for a in items if a["id"] in (warn.id, crit.id, acked.id)]
    assert order == [crit.id, warn.id, acked.id]


def test_summary_unread_and_seen(db):
    user = _user(db)
    rule = _rule(db, "noc.device_unreachable")
    api.mark_seen(current_user=user, db=db)
    before = api.alerts_summary(current_user=user, db=db)["unread"]
    _raise(db, rule, at=datetime.utcnow() + timedelta(seconds=5))
    s = api.alerts_summary(current_user=user, db=db)
    assert s["unread"] == before + 1 and s["latest"]
    from app.models.notification import AlertSeen
    db.get(AlertSeen, user.id).seen_at = datetime.utcnow() + timedelta(minutes=1)
    db.flush()
    assert api.alerts_summary(current_user=user, db=db)["unread"] == 0


def _rule_in(**kw):
    data = dict(name="Core down", event_type="noc.device_unreachable", severity="critical", params={"polls": 3},
                channels=["email"], recipients={"roles": ["admin"]})
    data.update(kw)
    return api.RuleIn(**data)


def test_rule_validation(db):
    user = _user(db)
    with pytest.raises(HTTPException, match="between"):
        api.create_rule(_rule_in(params={"polls": 0}), current_user=user, db=db)
    with pytest.raises(HTTPException, match="not a setting"):
        api.create_rule(_rule_in(params={"bogus": 1}), current_user=user, db=db)
    with pytest.raises(HTTPException, match="Unknown channel"):
        api.create_rule(_rule_in(channels=["webhook:999999"]), current_user=user, db=db)
    with pytest.raises(HTTPException, match="quiet hours"):
        api.create_rule(_rule_in(quiet_start="22:00"), current_user=user, db=db)
    with pytest.raises(HTTPException, match="at least one asset"):
        api.create_rule(_rule_in(asset_scope="specific"), current_user=user, db=db)
    with pytest.raises(HTTPException, match="Unknown event"):
        api.create_rule(_rule_in(event_type="nope"), current_user=user, db=db)
    with pytest.raises(ValueError):
        _rule_in(quiet_start="25:00", quiet_end="07:00")
    with pytest.raises(ValueError):
        _rule_in(recipients={"phones": ["abc"]})


def test_rule_crud_and_disable_closes_alerts(db):
    user = _user(db)
    out = api.create_rule(_rule_in(recipients={"roles": ["admin"], "emails": ["noc@example.com"]}),
                          current_user=user, db=db)
    assert out["summary"] == "No SNMP answer for 3 polls in a row" and "Admins" in out["who"]
    rule = db.get(NotificationRule, out["id"])
    alert = _raise(db, rule)
    out = api.set_rule_enabled(rule.id, api.EnabledIn(enabled=False), current_user=user, db=db)
    assert out["enabled"] is False
    db.refresh(alert)
    assert alert.status == "resolved"
    with pytest.raises(HTTPException) as exc:
        api.update_rule(rule.id, _rule_in(event_type="system.disk_low"), current_user=user, db=db)
    assert exc.value.status_code == 422
    assert api.delete_rule(rule.id, current_user=user, db=db) == {"success": True}


def test_builtin_rule_cannot_be_deleted(db):
    user = _user(db)
    rule = _rule(db, "system.disk_low", builtin=True)
    with pytest.raises(HTTPException) as exc:
        api.delete_rule(rule.id, current_user=user, db=db)
    assert exc.value.status_code == 409


def test_list_rules_groups_by_module(db):
    user = _user(db)
    groups = api.list_rules(_user=user, db=db)["groups"]
    assert [g["module"] for g in groups] == ["noc", "cve", "audit", "backup", "system"]
    assert any(r["event_type"] == "noc.device_unreachable" for r in groups[0]["rules"])


def test_webhook_lifecycle(db):
    user = _user(db)
    with patch.object(ch, "check_webhook_url", lambda url: url):
        out = api.create_webhook(api.WebhookIn(name="ops-chat", url="https://chat.example.com/h"),
                                 current_user=user, db=db)
    assert len(out["secret"]) >= 32
    hook = db.get(NotificationWebhook, out["id"])
    assert decrypt(hook.secret_encrypted, PURPOSE_NOTIFICATIONS) == out["secret"]
    assert out["secret"] not in hook.secret_encrypted
    rule = _rule(db, "noc.device_unreachable", channels=["email", f"webhook:{hook.id}"])
    with patch.object(ch, "check_webhook_url", lambda url: url):
        rotated = api.update_webhook(hook.id, api.WebhookIn(name="ops", url="https://chat.example.com/h",
                                                            rotate_secret=True), current_user=user, db=db)
    assert rotated["secret"] != out["secret"]
    api.delete_webhook(hook.id, current_user=user, db=db)
    db.refresh(rule)
    assert rule.channels == ["email"]


def test_webhook_url_rejected_by_api(db):
    user = _user(db)
    with pytest.raises(HTTPException) as exc:
        api.create_webhook(api.WebhookIn(name="x", url="http://127.0.0.1/hook"), current_user=user, db=db)
    assert exc.value.status_code == 422


def test_rule_test_send_reports_results(db):
    user = _user(db)
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["a@example.com"]}, channels=["email"])
    with patch.object(ch, "send_email", side_effect=ch.DeliveryError("SMTP error: auth")):
        out = api.test_rule(rule.id, current_user=user, db=db)
    assert out["results"] == [{"channel": "email", "recipient": "a@example.com", "success": False,
                               "message": "SMTP error: auth"}]
    rule.recipients = {}
    db.flush()
    with pytest.raises(HTTPException, match="Nobody to send to"):
        api.test_rule(rule.id, current_user=user, db=db)


def test_delivery_log(db):
    user = _user(db)
    rule = _rule(db, "noc.device_unreachable", recipients={"emails": ["log@example.com"]}, channels=["email"])
    _raise(db, rule)
    engine.dispatch(db, NOW)
    out = api.list_deliveries(channel="email", status="pending", search="log@example.com", offset=0, limit=50,
                              _user=user, db=db)
    assert out["total"] == 1 and out["items"][0]["rule_name"] == rule.name


def test_user_phone_validation():
    from app.schemas.user import UserUpdate
    assert UserUpdate(phone="0912 123-4567").phone == "09121234567"
    assert UserUpdate(phone="").phone == ""
    with pytest.raises(ValueError):
        UserUpdate(phone="12ab")


# ---------------------------------------------------------------------------
# CVE, audit and scheduling checks
# ---------------------------------------------------------------------------

def _finding(asset, cve, cvss, kev):
    return {"asset_id": asset.id, "asset_name": asset.asset_name, "ip_address": asset.ip_address,
            "product": "FortiOS 7.2.4", "cve_id": cve, "cvss": cvss, "kev": kev}


def test_cve_checks_group_findings_per_asset(db):
    fw = _asset(db, "fw")
    srv = _asset(db, "srv")
    findings = [_finding(fw, "CVE-2024-21762", 9.8, True), _finding(fw, "CVE-2023-27997", 9.2, True),
                _finding(srv, "CVE-2024-0001", 9.1, False), _finding(srv, "CVE-2024-0002", 5.0, False)]
    kev = _rule(db, "cve.kev_finding")
    crit = _rule(db, "cve.critical_finding")
    with patch("app.modules.alerts.events._cve_loaded", return_value=True), \
            patch("app.modules.cve.findings.compute", return_value={"findings": findings}) as compute:
        engine.evaluate(db, NOW, force=True, only=["cve.kev_finding", "cve.critical_finding"])
    [k] = _alerts(db, kev)
    assert k.asset_id == fw.id and "CVE-2024-21762, CVE-2023-27997" in k.detail
    assert sorted(a.asset_id for a in _alerts(db, crit)) == sorted([fw.id, srv.id])
    assert compute.call_count == 2


def test_cve_checks_quiet_without_database(db):
    rule = _rule(db, "cve.kev_finding")
    with patch("app.modules.alerts.events._cve_loaded", return_value=False):
        engine.evaluate(db, NOW, force=True, only=["cve.kev_finding"])
    assert _alerts(db, rule) == []


def test_compliance_drop(db):
    from app.models.audit import AuditSession, DeviceType
    owner = _user(db)
    asset = _asset(db)

    def session(pct, at):
        s = AuditSession(user_id=owner.id, asset_id=asset.id, target_ip=asset.ip_address,
                         device_type=DeviceType.LINUX, status="completed", started_at=at, completed_at=at,
                         compliance_pct=pct)
        db.add(s)
        db.flush()
        return s

    session(82, NOW - timedelta(days=30))
    small = session(78, NOW - timedelta(hours=3))
    big = session(64, NOW - timedelta(hours=1))
    rule = _rule(db, "audit.compliance_drop")
    engine.evaluate(db, NOW, force=True, only=["audit.compliance_drop"])
    [alert] = _alerts(db, rule)
    assert alert.fingerprint.endswith(f"audit:{big.id}") and "78% -> 64%" in alert.detail
    assert alert.owner_user_id == owner.id and small.id != big.id


def test_scheduled_job_failure(db):
    from app.models.scheduling import ScheduledJob, ScheduledJobRun
    owner = _user(db)
    asset = _asset(db)
    job = ScheduledJob(job_name="Nightly CIS", job_type="audit", technology="linux", asset_id=asset.id,
                       params_encrypted="x", recurrence="daily", hour=2, minute=0, enabled=True,
                       next_run_at=NOW + timedelta(hours=16), created_by=owner.id)
    db.add(job)
    db.flush()
    db.add(ScheduledJobRun(job_id=job.id, started_at=NOW - timedelta(hours=8),
                           finished_at=NOW - timedelta(hours=8), status="failed",
                           message="SSH authentication failed"))
    db.add(ScheduledJobRun(job_id=job.id, started_at=NOW - timedelta(hours=7),
                           finished_at=NOW - timedelta(hours=7), status="success"))
    db.flush()
    rule = _rule(db, "audit.scheduled_failed", recipients={"owner": True}, channels=["email"])
    engine.evaluate(db, NOW, force=True, only=["audit.scheduled_failed"])
    [alert] = _alerts(db, rule)
    assert alert.title == "Scheduled audit failed" and "SSH authentication failed" in alert.detail
    engine.dispatch(db, NOW)
    assert [d.recipient for d in _deliveries(db, rule)] == [owner.email]


def test_compose_texts():
    rule_name = "Device unreachable"
    a = SimpleNamespace(severity="critical", title="Device unreachable", source_label="RTR · 10.0.0.1",
                        detail="No answer", first_seen_at=NOW, resolved_at=None)
    subject, body, sms = engine.compose("raised", rule_name, [a])
    assert subject == "[Critical] Device unreachable - RTR · 10.0.0.1"
    assert "No answer" in body and "Since 2026-10-01 10:00 UTC" in body and "Acknowledge" in body
    assert sms == "NGCorion Critical: Device unreachable - RTR · 10.0.0.1"
    b = SimpleNamespace(**{**a.__dict__, "severity": "warning"})
    subject, body, sms = engine.compose("raised", rule_name, [a, b])
    assert subject == "[Critical] 2 alerts: Device unreachable" and "2 new alerts" in body
