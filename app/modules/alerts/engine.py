"""
The alert engine: turns what the evaluators see into alerts, and alerts into
messages.

One cycle (every CYCLE_SECONDS, in one worker - see AlertEngine):

  1. evaluate   each enabled rule whose event type is due is checked. A new
                problem raises an alert; a state alert whose problem is gone
                resolves by itself.
  2. dispatch   new alerts, reminders and "resolved" notices become delivery
                rows, one per recipient and channel. Bursts are grouped per
                rule; SMS waits out quiet hours unless the alert is Critical.
  3. send       pending deliveries go out. A failure is retried after 1 and 5
                minutes before it is marked failed.

Everything is in the database, so another worker can take over a cycle at any
point without losing or repeating a message.
"""
import asyncio
import logging
import time as _time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.credential_crypto import PURPOSE_NOTIFICATIONS, decrypt
from app.models import Asset, User
from app.models.risk import AssetRiskProfile
from app.models.notification import (ALERT_ACKNOWLEDGED, ALERT_ACTIVE, ALERT_OPEN_STATUSES, ALERT_RESOLVED,
                                     CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_SYSLOG, CHANNEL_WEBHOOK, Alert,
                                     NotificationDelivery, NotificationRule, NotificationWebhook)
from app.models.system_config import SECTION_SMS, SECTION_SMTP, SECTION_SYSLOG
from app.modules.alerts import channels as ch
from app.modules.alerts.events import EVENTS, EventType, Problem

logger = logging.getLogger(__name__)

CYCLE_SECONDS = 30
EVENT_LOOKBACK = timedelta(hours=24)
RETRY_DELAYS = (timedelta(minutes=1), timedelta(minutes=5))   # then failed
SEND_BATCH = 200
RETENTION_DAYS = 90
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
SEVERITY_LABEL = {"critical": "Critical", "warning": "Warning", "info": "Info"}
HOLD_PARAM = {"system.task_stopped": "minutes"}   # raise only after the problem lasts this long

# In the worker running the engine: when each event type was last checked, and
# since when a held problem has been seen.
_last_checked: Dict[str, float] = {}
_held_since: Dict[str, datetime] = {}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_params(rule: NotificationRule) -> Dict:
    event = EVENTS.get(rule.event_type)
    values = {p.key: p.default for p in (event.params if event else [])}
    values.update(rule.params or {})
    return values


def ensure_default_rules(db: Session) -> int:
    """One built-in rule per event type, created once. Safe from several workers."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('ngcorion:notification-rules-seed'))"))
    have = {r[0] for r in db.query(NotificationRule.event_type).filter(NotificationRule.builtin.is_(True))}
    created = 0
    for event in EVENTS.values():
        if event.code in have:
            continue
        db.add(NotificationRule(
            event_type=event.code, name=event.name, enabled=event.enabled, severity=event.severity,
            params={p.key: p.default for p in event.params}, asset_scope="all", asset_filter={},
            recipients={"roles": list(event.roles), "user_ids": [], "emails": [], "phones": [],
                        "owner": event.has_owner},
            channels=list(event.channels), repeat_minutes=event.repeat_minutes, notify_resolved=True,
            quiet_start="22:00" if CHANNEL_SMS in event.channels else None,
            quiet_end="07:00" if CHANNEL_SMS in event.channels else None,
            group_minutes=5 if event.uses_assets else 0, builtin=True))
        created += 1
    db.commit()
    return created


def _asset_matcher(db: Session, rules: Iterable[NotificationRule]):
    """asset_id -> (asset type id, risk zone id) when a rule filters by them.
    The zone is the one set for the asset in Risk Intelligence."""
    if not any(r.asset_scope == "matching" for r in rules):
        return {}
    rows = (db.query(Asset.id, Asset.asset_type_id, AssetRiskProfile.zone_id)
            .outerjoin(AssetRiskProfile, AssetRiskProfile.asset_id == Asset.id).all())
    return {r[0]: (r[1], r[2]) for r in rows}


def in_scope(rule: NotificationRule, asset_id: Optional[int], assets: Dict) -> bool:
    if rule.asset_scope == "all" or asset_id is None:
        return True
    f = rule.asset_filter or {}
    if rule.asset_scope == "specific":
        return asset_id in set(f.get("asset_ids") or [])
    type_id, zone_id = assets.get(asset_id, (None, None))
    types = set(f.get("type_ids") or [])
    zones = set(f.get("zone_ids") or [])
    return (not types or type_id in types) and (not zones or zone_id in zones)


# ---------------------------------------------------------------------------
# 1. Evaluate
# ---------------------------------------------------------------------------

def evaluate(db: Session, now: Optional[datetime] = None, force: bool = False,
             only: Optional[Iterable[str]] = None) -> Dict[str, int]:
    now = now or datetime.utcnow()
    clock = _time.monotonic()
    rules = db.query(NotificationRule).filter(NotificationRule.enabled.is_(True)).all()
    by_event: Dict[str, List[NotificationRule]] = defaultdict(list)
    for r in rules:
        if r.event_type in EVENTS and (only is None or r.event_type in only):
            by_event[r.event_type].append(r)
    assets = _asset_matcher(db, rules)
    stats = {"raised": 0, "resolved": 0}

    for code, event_rules in by_event.items():
        event = EVENTS[code]
        if not force and clock - _last_checked.get(code, -1e9) < event.every:
            continue
        _last_checked[code] = clock
        cache: Dict[str, List[Problem]] = {}
        for rule in event_rules:
            params = rule_params(rule)
            since = max(rule.created_at or now, now - EVENT_LOOKBACK)
            key = repr(sorted(params.items())) + (since.isoformat() if event.kind == "event" else "")
            try:
                if key not in cache:
                    with db.begin_nested():     # a failed query must not abort the rest of the cycle
                        cache[key] = event.evaluate(db, params, now, since)
            except Exception:
                logger.exception("[alerts] %s check failed", code)
                continue
            problems = [p for p in cache[key] if in_scope(rule, p.asset_id, assets)]
            raised, resolved = _apply(db, rule, event, problems, params, now)
            stats["raised"] += raised
            stats["resolved"] += resolved
    return stats


def _apply(db: Session, rule: NotificationRule, event: EventType, problems: List[Problem], params: Dict,
           now: datetime) -> Tuple[int, int]:
    prefix = f"{rule.id}:"
    seen = {prefix + p.key: p for p in problems}
    open_alerts = {a.fingerprint: a for a in db.query(Alert).filter(
        Alert.rule_id == rule.id, Alert.status.in_(ALERT_OPEN_STATUSES))}
    known = set(open_alerts)
    if event.kind == "event" and seen:
        known |= {f for (f,) in db.query(Alert.fingerprint).filter(Alert.fingerprint.in_(list(seen)))}

    hold = HOLD_PARAM.get(event.code)
    raised = resolved = 0
    for fp, p in seen.items():
        alert = open_alerts.get(fp)
        if alert is not None:
            alert.last_seen_at = now
            alert.title, alert.detail, alert.source_label = p.title, p.detail, p.source_label
            alert.severity = rule.severity
            continue
        if fp in known:
            continue
        if hold:
            first = _held_since.setdefault(fp, now)
            if now - first < timedelta(minutes=float(params.get(hold, 0))):
                continue
        try:
            with db.begin_nested():
                db.add(Alert(rule_id=rule.id, event_type=event.code, module=event.module, severity=rule.severity,
                             fingerprint=fp, title=p.title, detail=p.detail, asset_id=p.asset_id,
                             source_label=p.source_label, link=p.link, owner_user_id=p.owner_user_id,
                             status=ALERT_ACTIVE, first_seen_at=now, last_seen_at=now))
        except IntegrityError:
            continue        # another worker raised it a moment ago
        rule.last_fired_at = now
        raised += 1
    for fp in [f for f in _held_since if f.startswith(prefix) and f not in seen]:
        _held_since.pop(fp, None)

    if event.kind == "state":
        for fp, alert in open_alerts.items():
            if fp in seen:
                continue
            alert.status = ALERT_RESOLVED
            alert.resolved_at = now
            alert.resolved_by = None
            if rule.notify_resolved and alert.notified_at is not None and rule.channels:
                alert.resolved_notice_pending = True
            resolved += 1
    db.commit()
    return raised, resolved


# ---------------------------------------------------------------------------
# 2. Dispatch
# ---------------------------------------------------------------------------

def _base_url() -> Optional[str]:
    base = (settings.FRONTEND_BASE_URL or "").rstrip("/")
    return None if not base or "localhost" in base or "127.0.0.1" in base else base


def alert_payload(alert: Alert, asset: Optional[Asset] = None) -> Dict:
    base = _base_url()
    return {
        "alert_id": alert.id, "event_type": alert.event_type, "module": alert.module,
        "severity": alert.severity, "status": alert.status, "title": alert.title, "detail": alert.detail,
        "source": alert.source_label, "asset_id": alert.asset_id,
        "asset_name": asset.asset_name if asset else None, "asset_ip": asset.ip_address if asset else None,
        "first_seen_at": alert.first_seen_at.isoformat() + "Z" if alert.first_seen_at else None,
        "resolved_at": alert.resolved_at.isoformat() + "Z" if alert.resolved_at else None,
        "url": f"{base}{alert.link}" if base and alert.link else None,
        "time_ms": int((alert.last_seen_at or alert.first_seen_at).timestamp() * 1000)
        if (alert.last_seen_at or alert.first_seen_at) else None,
    }


def _when(dt: Optional[datetime], tz) -> str:
    if dt is None:
        return ""
    if tz is None:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    from datetime import timezone
    return dt.replace(tzinfo=timezone.utc).astimezone(tz).strftime("%Y-%m-%d %H:%M")


def compose(kind: str, rule_name: str, alerts: List[Alert], tz=None) -> Tuple[str, str, str]:
    """(subject, text body, sms text) for a message about these alerts."""
    worst = min((a.severity for a in alerts), key=lambda s: SEVERITY_RANK.get(s, 3))
    tag = {"reminder": "Reminder", "resolved": "Resolved", "test": "Test"}.get(kind, SEVERITY_LABEL.get(worst, worst))
    one = alerts[0]
    if len(alerts) == 1:
        subject = f"[{tag}] {one.title}" + (f" - {one.source_label}" if one.source_label else "")
    else:
        subject = f"[{tag}] {len(alerts)} alerts: {rule_name}"
    lines = []
    intro = {"raised": "New alert" if len(alerts) == 1 else f"{len(alerts)} new alerts",
             "reminder": "Still not acknowledged", "resolved": "Resolved", "test": "Test message"}[kind]
    lines.append(f"{intro} - {rule_name}\n")
    for a in alerts:
        lines.append(f"* {SEVERITY_LABEL.get(a.severity, a.severity)}: {a.title}"
                     + (f" - {a.source_label}" if a.source_label else ""))
        if a.detail:
            lines.append(f"  {a.detail}")
        when = _when(a.resolved_at if kind == "resolved" else a.first_seen_at, tz)
        if when:
            lines.append(f"  {'Resolved' if kind == 'resolved' else 'Since'} {when}")
        lines.append("")
    base = _base_url()
    if kind in ("raised", "reminder"):
        lines.append("Acknowledge it in NGCorion so the team knows someone is on it"
                     + (f": {base}/alerts" if base else " (Alerts page)."))
    body = "\n".join(lines).strip() + "\n"
    if len(alerts) == 1:
        sms = f"NGCorion {tag}: {one.title}" + (f" - {one.source_label}" if one.source_label else "")
    else:
        sms = f"NGCorion {tag}: {len(alerts)} alerts - {rule_name}"
    return subject[:255], body, sms[:300]


def _recipients(db: Session, rule: NotificationRule, alerts: List[Alert]) -> Tuple[List[str], List[str]]:
    r = rule.recipients or {}
    users = []
    roles = [x for x in (r.get("roles") or []) if x]
    ids = set(r.get("user_ids") or [])
    if r.get("owner"):
        ids |= {a.owner_user_id for a in alerts if a.owner_user_id}
    if roles or ids:
        from app.models.user import UserRole
        role_values = [UserRole(x) for x in roles if x in {e.value for e in UserRole}]
        q = db.query(User).filter(User.is_active.is_(True))
        conds = []
        if role_values:
            conds.append(User.role.in_(role_values))
        if ids:
            conds.append(User.id.in_(ids))
        users = q.filter(or_(*conds)).all() if conds else []
    emails = {u.email.strip().lower() for u in users if u.email}
    emails |= {e.strip().lower() for e in (r.get("emails") or []) if e and e.strip()}
    phones = {u.phone for u in users if u.phone}
    phones |= {p.strip() for p in (r.get("phones") or []) if p and p.strip()}
    return sorted(emails), sorted(phones)


def _in_quiet_hours(rule: NotificationRule, now: datetime, tz) -> bool:
    if not rule.quiet_start or not rule.quiet_end:
        return False
    from datetime import timezone
    local = now.replace(tzinfo=timezone.utc).astimezone(tz) if tz else now
    hm = local.strftime("%H:%M")
    start, end = rule.quiet_start, rule.quiet_end
    return start <= hm < end if start <= end else (hm >= start or hm < end)


def queue_message(db: Session, rule: NotificationRule, kind: str, alerts: List[Alert], now: datetime,
                  tz=None, channels: Optional[List[str]] = None) -> List[NotificationDelivery]:
    """Delivery rows for one message about `alerts` on the rule's channels."""
    channels = rule.channels if channels is None else channels
    if not channels or not alerts:
        return []
    subject, body, sms = compose(kind, rule.name, alerts, tz)
    worst = min((a.severity for a in alerts), key=lambda s: SEVERITY_RANK.get(s, 3))
    emails, phones = _recipients(db, rule, alerts)
    ids = [a.id for a in alerts if a.id]
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_([x.asset_id for x in alerts if x.asset_id]))}
    payloads = [alert_payload(a, assets.get(a.asset_id)) for a in alerts]
    rows: List[NotificationDelivery] = []

    def add(channel, recipient, subj, text_body, payload=None, webhook_id=None, status="pending", error=None):
        d = NotificationDelivery(alert_ids=ids, rule_id=rule.id, channel=channel, webhook_id=webhook_id,
                                 recipient=recipient, kind=kind, severity=worst, subject=subj, body=text_body,
                                 payload=payload, status=status, error=error, attempts=0, next_attempt_at=now,
                                 created_at=now)
        db.add(d)
        rows.append(d)

    for channel in channels:
        if channel == CHANNEL_EMAIL:
            for to in emails:
                add(CHANNEL_EMAIL, to, subject, body)
        elif channel == CHANNEL_SMS:
            quiet = kind != "test" and worst != "critical" and _in_quiet_hours(rule, now, tz)
            for phone in phones:
                if quiet:
                    add(CHANNEL_SMS, phone, subject, sms, status="skipped",
                        error=f"Quiet hours {rule.quiet_start}-{rule.quiet_end}")
                else:
                    add(CHANNEL_SMS, phone, subject, sms)
        elif channel == CHANNEL_SYSLOG:
            for p in payloads:                      # SIEMs expect one event per alert
                add(CHANNEL_SYSLOG, None, subject, body, payload={**p, "kind": kind})
        elif channel.startswith(CHANNEL_WEBHOOK + ":"):
            try:
                hook_id = int(channel.split(":", 1)[1])
            except ValueError:
                continue
            add(CHANNEL_WEBHOOK, None, subject, body, webhook_id=hook_id, payload={
                "kind": kind, "sent_at": now.isoformat() + "Z",
                "rule": {"id": rule.id, "name": rule.name, "event_type": rule.event_type},
                "summary": subject, "alerts": payloads})
    return rows


def dispatch(db: Session, now: Optional[datetime] = None) -> int:
    now = now or datetime.utcnow()
    tz = ch.local_timezone(db)
    queued = 0
    rules = {r.id: r for r in db.query(NotificationRule).all()}

    pending = defaultdict(list)
    for a in db.query(Alert).filter(Alert.notified_at.is_(None), Alert.status.in_(ALERT_OPEN_STATUSES)):
        pending[a.rule_id].append(a)
    for rule_id, alerts in pending.items():
        rule = rules.get(rule_id)
        if rule is None or not rule.enabled or not rule.channels:
            for a in alerts:
                a.notified_at = a.last_notified_at = now        # in-app only
            continue
        if rule.group_minutes and rule.last_sent_at and now - rule.last_sent_at < timedelta(minutes=rule.group_minutes):
            continue                                            # collect this burst into one message
        active = sorted([a for a in alerts if a.status == ALERT_ACTIVE],
                        key=lambda a: (SEVERITY_RANK.get(a.severity, 3), a.id))
        if active:
            queued += len(queue_message(db, rule, "raised", active, now, tz))
            rule.last_sent_at = now
        for a in alerts:
            a.notified_at = a.last_notified_at = now

    for rule in rules.values():
        if not rule.enabled or not rule.repeat_minutes or not rule.channels:
            continue
        due = (db.query(Alert).filter(Alert.rule_id == rule.id, Alert.status == ALERT_ACTIVE,
                                      Alert.notified_at.isnot(None),
                                      Alert.last_notified_at <= now - timedelta(minutes=rule.repeat_minutes))
               .order_by(Alert.id).all())
        if due:
            queued += len(queue_message(db, rule, "reminder", due, now, tz))
            for a in due:
                a.last_notified_at = now
                a.reminders_sent = (a.reminders_sent or 0) + 1

    done = defaultdict(list)
    for a in db.query(Alert).filter(Alert.resolved_notice_pending.is_(True)):
        done[a.rule_id].append(a)
        a.resolved_notice_pending = False
    for rule_id, alerts in done.items():
        rule = rules.get(rule_id)
        if rule is not None and rule.channels:
            queued += len(queue_message(db, rule, "resolved", alerts, now, tz))
    db.commit()
    return queued


# ---------------------------------------------------------------------------
# 3. Send
# ---------------------------------------------------------------------------

class _Configs:
    """System Configuration sections and webhooks, read once per send pass."""

    def __init__(self, db: Session):
        self.db = db
        self._sections: Dict[str, Dict] = {}
        self._hooks: Dict[int, Optional[NotificationWebhook]] = {}

    def section(self, name: str) -> Dict:
        if name not in self._sections:
            self._sections[name] = ch.load_section(self.db, name)
        return self._sections[name]

    def hook(self, hook_id: int) -> Optional[NotificationWebhook]:
        if hook_id not in self._hooks:
            self._hooks[hook_id] = self.db.get(NotificationWebhook, hook_id)
        return self._hooks[hook_id]


def deliver(db: Session, d: NotificationDelivery, configs: Optional[_Configs] = None) -> None:
    """Send one delivery now. Raises ch.DeliveryError."""
    configs = configs or _Configs(db)
    if d.channel == CHANNEL_EMAIL:
        ch.send_email(configs.section(SECTION_SMTP), [d.recipient], d.subject, d.body)
    elif d.channel == CHANNEL_SMS:
        ch.send_sms(configs.section(SECTION_SMS), d.recipient, d.body)
    elif d.channel == CHANNEL_SYSLOG:
        ch.send_syslog(configs.section(SECTION_SYSLOG), d.payload or {})
    elif d.channel == CHANNEL_WEBHOOK:
        hook = configs.hook(d.webhook_id) if d.webhook_id else None
        if hook is None:
            raise ch.DeliveryError("The webhook was deleted")
        if not hook.enabled:
            raise ch.DeliveryError("The webhook is turned off")
        try:
            secret = decrypt(hook.secret_encrypted, PURPOSE_NOTIFICATIONS)
        except ValueError as exc:
            raise ch.DeliveryError(str(exc)) from exc
        try:
            ch.send_webhook(hook.url, secret, d.payload or {})
        except ch.DeliveryError as exc:
            hook.last_error, hook.last_error_at = str(exc), datetime.utcnow()
            raise
        hook.last_success_at = datetime.utcnow()
    else:
        raise ch.DeliveryError(f"Unknown channel {d.channel}")


def send_pending(db: Session, now: Optional[datetime] = None, limit: int = SEND_BATCH) -> Dict[str, int]:
    now = now or datetime.utcnow()
    rows = (db.query(NotificationDelivery)
            .filter(NotificationDelivery.status == "pending", NotificationDelivery.next_attempt_at <= now)
            .order_by(NotificationDelivery.id).limit(limit).with_for_update(skip_locked=True).all())
    configs = _Configs(db)
    stats = {"sent": 0, "retry": 0, "failed": 0}
    for d in rows:
        d.attempts = (d.attempts or 0) + 1
        try:
            deliver(db, d, configs)
        except ch.DeliveryError as exc:
            d.error = str(exc)[:1000]
            if d.attempts > len(RETRY_DELAYS):
                d.status = "failed"
                stats["failed"] += 1
            else:
                d.next_attempt_at = now + RETRY_DELAYS[d.attempts - 1]
                stats["retry"] += 1
        except Exception as exc:    # a bug must not stop the queue
            logger.exception("[alerts] delivery %s crashed", d.id)
            d.status, d.error = "failed", f"{exc.__class__.__name__}"
            stats["failed"] += 1
        else:
            d.status, d.sent_at = "sent", datetime.utcnow()
            stats["sent"] += 1
        db.commit()
    return stats


def cleanup(db: Session, now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=RETENTION_DAYS)
    db.query(NotificationDelivery).filter(NotificationDelivery.created_at < cutoff).delete(synchronize_session=False)
    db.query(Alert).filter(Alert.status == ALERT_RESOLVED, Alert.resolved_at < cutoff).delete(synchronize_session=False)
    db.commit()


# ---------------------------------------------------------------------------
# Lifecycle actions (from the API)
# ---------------------------------------------------------------------------

def acknowledge(db: Session, alert: Alert, user_id: int, now: Optional[datetime] = None) -> None:
    if alert.status != ALERT_ACTIVE:
        return
    alert.status = ALERT_ACKNOWLEDGED
    alert.acknowledged_at = now or datetime.utcnow()
    alert.acknowledged_by = user_id


def resolve(db: Session, alert: Alert, user_id: Optional[int], now: Optional[datetime] = None) -> None:
    if alert.status == ALERT_RESOLVED:
        return
    alert.status = ALERT_RESOLVED
    alert.resolved_at = now or datetime.utcnow()
    alert.resolved_by = user_id
    alert.resolved_notice_pending = False   # a person closed it; nobody needs to be told


# ---------------------------------------------------------------------------
# Background runner
# ---------------------------------------------------------------------------

def run_cycle(now: Optional[datetime] = None) -> None:
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        if not getattr(run_cycle, "_seeded", False):
            ensure_default_rules(db)
            run_cycle._seeded = True
        evaluate(db, now)
        dispatch(db, now)
        send_pending(db, now)
        today = (now or datetime.utcnow()).date()
        if getattr(run_cycle, "_cleaned", None) != today:
            cleanup(db, now)
            run_cycle._cleaned = today
    except Exception:
        logger.exception("[alerts] cycle failed")
        db.rollback()
    finally:
        db.close()


class AlertEngine:
    def __init__(self, interval: int = CYCLE_SECONDS):
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.to_thread(run_cycle)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            _last_checked.clear()
            self._task = asyncio.create_task(self._loop(), name="alert-engine")
            logger.info("[alerts] engine started (every %ss)", self.interval)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=20)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_engine: Optional[AlertEngine] = None


def start_alert_engine() -> None:
    global _engine
    if _engine is None:
        _engine = AlertEngine()
    _engine.start()


async def stop_alert_engine() -> None:
    if _engine is not None:
        await _engine.stop()
