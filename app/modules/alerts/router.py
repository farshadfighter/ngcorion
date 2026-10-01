"""
Alerts API.

  /api/alerts          the Alerts page, the header bell and the sidebar badge.
                       Every signed-in user sees the alerts of the modules they
                       can read (NOC alerts need NOC read, and so on).
  /api/notifications   rules, channels, webhooks and the delivery log, under
                       System > Notifications (System Configuration permission).
"""
import re
from datetime import datetime, timedelta
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.credential_crypto import PURPOSE_NOTIFICATIONS, decrypt, encrypt
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import Asset, AssetType, User, UserPermission, log_action
from app.models.risk import RiskZone
from app.models.notification import (ALERT_ACKNOWLEDGED, ALERT_ACTIVE, ALERT_OPEN_STATUSES, ALERT_RESOLVED,
                                     CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_SYSLOG, CHANNEL_WEBHOOK, SEVERITIES,
                                     Alert, AlertSeen, NotificationDelivery, NotificationRule,
                                     NotificationWebhook)
from app.models.system_config import SECTION_SMS, SECTION_SMTP, SECTION_SYSLOG
from app.models.user import UserRole
from app.modules.alerts import channels as ch
from app.modules.alerts import engine
from app.modules.alerts.events import EVENTS, MODULE_LABELS, MODULE_ORDER
from app.schemas.user import validate_phone

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])
admin_router = APIRouter(prefix="/api/notifications", tags=["Notifications"])

# Alert module -> the permission module that may see it.
MODULE_PERMISSION = {"noc": "noc", "cve": "cve", "audit": "auditing", "backup": "backup", "system": "system_config"}
BELL_ITEMS = 8


def visible_modules(db: Session, user: User) -> List[str]:
    if user.role == UserRole.ADMIN:
        return list(MODULE_PERMISSION)
    readable = {(p.module.value if hasattr(p.module, "value") else str(p.module)).lower()
                for p in db.query(UserPermission).filter(UserPermission.user_id == user.id,
                                                         UserPermission.can_read.is_(True))}
    return [m for m, perm in MODULE_PERMISSION.items() if perm in readable]


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _usernames(db: Session, ids) -> Dict[int, str]:
    ids = {i for i in ids if i}
    return {u.id: u.username for u in db.query(User).filter(User.id.in_(ids))} if ids else {}


def _alert_rows(db: Session, alerts: List[Alert]) -> List[dict]:
    names = _usernames(db, [a.acknowledged_by for a in alerts] + [a.resolved_by for a in alerts])
    rules = {r.id: r.name for r in db.query(NotificationRule).filter(
        NotificationRule.id.in_({a.rule_id for a in alerts if a.rule_id}))} if alerts else {}
    return [{
        "id": a.id, "event_type": a.event_type, "module": a.module, "severity": a.severity, "status": a.status,
        "kind": EVENTS[a.event_type].kind if a.event_type in EVENTS else "event",
        "title": a.title, "detail": a.detail, "source": a.source_label, "asset_id": a.asset_id, "link": a.link,
        "rule_id": a.rule_id, "rule_name": rules.get(a.rule_id),
        "first_seen_at": _iso(a.first_seen_at), "last_seen_at": _iso(a.last_seen_at),
        "acknowledged_at": _iso(a.acknowledged_at), "acknowledged_by": names.get(a.acknowledged_by),
        "resolved_at": _iso(a.resolved_at), "resolved_by": names.get(a.resolved_by),
        "auto_resolved": a.status == ALERT_RESOLVED and a.resolved_by is None,
        "reminders_sent": a.reminders_sent or 0,
    } for a in alerts]


def _severity_order():
    return func.array_position(["critical", "warning", "info"], Alert.severity)


# ===========================================================================
# Alerts
# ===========================================================================

@router.get("")
def list_alerts(
    status: Literal["open", "acknowledged", "resolved"] = "open",
    module: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = Query(None, max_length=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    modules = visible_modules(db, current_user)
    base = db.query(Alert).filter(Alert.module.in_(modules))
    week_ago = datetime.utcnow() - timedelta(days=7)
    counts = {
        "open": base.filter(Alert.status.in_(ALERT_OPEN_STATUSES)).count(),
        "acknowledged": base.filter(Alert.status == ALERT_ACKNOWLEDGED).count(),
        "resolved": base.filter(Alert.status == ALERT_RESOLVED).count(),
    }
    stats = {
        "critical_unacknowledged": base.filter(Alert.status == ALERT_ACTIVE, Alert.severity == "critical").count(),
        "warning_open": base.filter(Alert.status.in_(ALERT_OPEN_STATUSES), Alert.severity == "warning").count(),
        "acknowledged": counts["acknowledged"],
        "resolved_7d": base.filter(Alert.status == ALERT_RESOLVED, Alert.resolved_at >= week_ago).count(),
    }

    q = base
    if status == "open":
        q = q.filter(Alert.status.in_(ALERT_OPEN_STATUSES))
    else:
        q = q.filter(Alert.status == (ALERT_ACKNOWLEDGED if status == "acknowledged" else ALERT_RESOLVED))
    if module:
        q = q.filter(Alert.module == module)
    if severity:
        q = q.filter(Alert.severity == severity)
    if search:
        like = f"%{search.strip()}%"
        q = q.filter(or_(Alert.title.ilike(like), Alert.detail.ilike(like), Alert.source_label.ilike(like)))
    by_module = dict(q.with_entities(Alert.module, func.count()).group_by(Alert.module).all()) if not module else None
    total = q.count()
    if status == "resolved":
        q = q.order_by(Alert.resolved_at.desc(), Alert.id.desc())
    else:
        # Unacknowledged first, then the most urgent, then the newest.
        q = q.order_by((Alert.status == ALERT_ACKNOWLEDGED).asc(), _severity_order(), Alert.first_seen_at.desc())
    items = q.offset(offset).limit(limit).all()
    return {"items": _alert_rows(db, items), "total": total, "counts": counts, "stats": stats,
            "modules": [{"key": m, "label": MODULE_LABELS[m], "count": (by_module or {}).get(m)}
                        for m in MODULE_ORDER if m in modules]}


@router.get("/summary")
def alerts_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The bell and the sidebar badge."""
    modules = visible_modules(db, current_user)
    seen = db.get(AlertSeen, current_user.id)
    open_q = db.query(Alert).filter(Alert.module.in_(modules), Alert.status.in_(ALERT_OPEN_STATUSES))
    unread_q = db.query(Alert).filter(Alert.module.in_(modules))
    if seen is not None:
        unread_q = unread_q.filter(Alert.first_seen_at > seen.seen_at)
    unread_q = unread_q.filter(Alert.status.in_(ALERT_OPEN_STATUSES))
    latest = (db.query(Alert).filter(Alert.module.in_(modules))
              .order_by(Alert.first_seen_at.desc(), Alert.id.desc()).limit(BELL_ITEMS).all())
    return {
        "open": open_q.count(),
        "unacknowledged": open_q.filter(Alert.status == ALERT_ACTIVE).count(),
        "critical": open_q.filter(Alert.status == ALERT_ACTIVE, Alert.severity == "critical").count(),
        "unread": unread_q.count(),
        "seen_at": _iso(seen.seen_at) if seen else None,
        "latest": _alert_rows(db, latest),
    }


@router.post("/seen")
def mark_seen(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(AlertSeen, current_user.id)
    if row is None:
        db.add(AlertSeen(user_id=current_user.id, seen_at=datetime.utcnow()))
    else:
        row.seen_at = datetime.utcnow()
    db.commit()
    return {"success": True}


def _own_alert(db: Session, alert_id: int, user: User) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.module not in visible_modules(db, user):
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = _own_alert(db, alert_id, current_user)
    if alert.status != ALERT_ACTIVE:
        raise HTTPException(status_code=409, detail=f"The alert is already {alert.status}")
    engine.acknowledge(db, alert, current_user.id)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="alert.acknowledge",
               module="alerts", target_id=alert.id, detail=f"Acknowledged '{alert.title}' ({alert.source_label})")
    return _alert_rows(db, [alert])[0]


@router.post("/{alert_id}/resolve")
def resolve_alert(alert_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Close an alert. A condition that still holds raises a new alert at the next check."""
    alert = _own_alert(db, alert_id, current_user)
    if alert.status == ALERT_RESOLVED:
        raise HTTPException(status_code=409, detail="The alert is already resolved")
    engine.resolve(db, alert, current_user.id)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="alert.resolve",
               module="alerts", target_id=alert.id, detail=f"Resolved '{alert.title}' ({alert.source_label})")
    return _alert_rows(db, [alert])[0]


# ===========================================================================
# Notifications: rules
# ===========================================================================

_HHMM = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")


class AssetFilter(BaseModel):
    type_ids: List[int] = Field(default_factory=list, max_length=200)
    zone_ids: List[int] = Field(default_factory=list, max_length=100)   # Risk Intelligence zones
    asset_ids: List[int] = Field(default_factory=list, max_length=2000)


class Recipients(BaseModel):
    roles: List[Literal["admin", "manager", "user", "guest"]] = Field(default_factory=list)
    user_ids: List[int] = Field(default_factory=list, max_length=500)
    emails: List[EmailStr] = Field(default_factory=list, max_length=50)
    phones: List[str] = Field(default_factory=list, max_length=50)
    owner: bool = False

    @field_validator("phones")
    @classmethod
    def _phones(cls, v: List[str]) -> List[str]:
        out = []
        for p in v:
            p = validate_phone(p)
            if p:
                out.append(p)
        return out


class RuleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    event_type: str
    enabled: bool = True
    severity: Literal["info", "warning", "critical"] = "warning"
    params: Dict[str, float] = Field(default_factory=dict)
    asset_scope: Literal["all", "matching", "specific"] = "all"
    asset_filter: AssetFilter = Field(default_factory=AssetFilter)
    recipients: Recipients = Field(default_factory=Recipients)
    channels: List[str] = Field(default_factory=list, max_length=20)
    repeat_minutes: int = Field(0, ge=0, le=10080)
    notify_resolved: bool = True
    quiet_start: Optional[str] = None
    quiet_end: Optional[str] = None
    group_minutes: int = Field(0, ge=0, le=120)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or "\n" in v or "\r" in v:
            raise ValueError("Enter a name on one line")
        return v

    @field_validator("quiet_start", "quiet_end")
    @classmethod
    def _hhmm(cls, v: Optional[str]) -> Optional[str]:
        if v in (None, ""):
            return None
        if not _HHMM.match(v):
            raise ValueError("Use HH:MM, e.g. 22:00")
        return v


def _validate_rule(db: Session, data: RuleIn) -> dict:
    event = EVENTS.get(data.event_type)
    if event is None:
        raise HTTPException(status_code=422, detail=f"Unknown event type {data.event_type}")
    params = {}
    allowed = {p.key: p for p in event.params}
    for key, value in data.params.items():
        p = allowed.get(key)
        if p is None:
            raise HTTPException(status_code=422, detail=f"'{key}' is not a setting of {event.name}")
        if not p.min <= value <= p.max:
            raise HTTPException(status_code=422, detail=f"{p.label} must be between {p.min:g} and {p.max:g}")
        params[key] = value
    for key, p in allowed.items():
        params.setdefault(key, p.default)

    channels = []
    hook_ids = {h.id for h in db.query(NotificationWebhook.id)}
    for c in dict.fromkeys(data.channels):
        if c in (CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_SYSLOG):
            channels.append(c)
        elif c.startswith(CHANNEL_WEBHOOK + ":") and c[len(CHANNEL_WEBHOOK) + 1:].isdigit() \
                and int(c.split(":", 1)[1]) in hook_ids:
            channels.append(c)
        else:
            raise HTTPException(status_code=422, detail=f"Unknown channel {c}")
    if bool(data.quiet_start) != bool(data.quiet_end):
        raise HTTPException(status_code=422, detail="Set both the start and the end of quiet hours, or neither")
    if data.asset_scope == "specific" and not data.asset_filter.asset_ids and event.uses_assets:
        raise HTTPException(status_code=422, detail="Pick at least one asset, or apply the rule to all assets")
    recipients = data.recipients.model_dump()
    recipients["emails"] = [str(e) for e in data.recipients.emails]
    if not event.has_owner:
        recipients["owner"] = False
    return {
        "name": data.name, "event_type": event.code, "enabled": data.enabled, "severity": data.severity,
        "params": params, "asset_scope": data.asset_scope if event.uses_assets else "all",
        "asset_filter": data.asset_filter.model_dump() if event.uses_assets else {},
        "recipients": recipients, "channels": channels, "repeat_minutes": data.repeat_minutes,
        "notify_resolved": data.notify_resolved, "quiet_start": data.quiet_start, "quiet_end": data.quiet_end,
        "group_minutes": data.group_minutes,
    }


def _who(rule: NotificationRule, users: Dict[int, str]) -> str:
    r = rule.recipients or {}
    parts = [{"admin": "Admins", "manager": "Managers", "user": "Users", "guest": "Guests"}.get(x, x)
             for x in r.get("roles") or []]
    parts += [users.get(i, f"user #{i}") for i in r.get("user_ids") or []]
    parts += list(r.get("emails") or [])
    parts += list(r.get("phones") or [])
    if r.get("owner"):
        parts.append("the person behind it")
    return ", ".join(parts) or "Nobody - in-app only"


def _rule_out(rule: NotificationRule, users: Dict[int, str], open_counts: Dict[int, int],
              hooks: Dict[int, str]) -> dict:
    event = EVENTS.get(rule.event_type)
    params = engine.rule_params(rule)
    return {
        "id": rule.id, "name": rule.name, "event_type": rule.event_type,
        "module": event.module if event else "system", "kind": event.kind if event else "state",
        "summary": event.describe(params) if event else rule.event_type,
        "enabled": rule.enabled, "severity": rule.severity, "params": params,
        "asset_scope": rule.asset_scope, "asset_filter": rule.asset_filter or {},
        "recipients": {"roles": [], "user_ids": [], "emails": [], "phones": [], "owner": False,
                       **(rule.recipients or {})},
        "who": _who(rule, users), "channels": rule.channels or [],
        "channel_labels": [_channel_label(c, hooks) for c in rule.channels or []],
        "repeat_minutes": rule.repeat_minutes, "notify_resolved": rule.notify_resolved,
        "quiet_start": rule.quiet_start, "quiet_end": rule.quiet_end, "group_minutes": rule.group_minutes,
        "builtin": rule.builtin, "last_fired_at": _iso(rule.last_fired_at),
        "open_alerts": open_counts.get(rule.id, 0), "updated_at": _iso(rule.updated_at),
    }


def _channel_label(c: str, hooks: Dict[int, str]) -> str:
    if c.startswith(CHANNEL_WEBHOOK + ":"):
        try:
            return f"Webhook · {hooks.get(int(c.split(':', 1)[1]), 'deleted')}"
        except ValueError:
            return c
    return {CHANNEL_EMAIL: "Email", CHANNEL_SMS: "SMS", CHANNEL_SYSLOG: "Syslog"}.get(c, c)


def _rule_context(db: Session):
    users = {u.id: u.username for u in db.query(User.id, User.username)}
    open_counts = dict(db.query(Alert.rule_id, func.count()).filter(Alert.status.in_(ALERT_OPEN_STATUSES))
                       .group_by(Alert.rule_id).all())
    hooks = {h.id: h.name for h in db.query(NotificationWebhook.id, NotificationWebhook.name)}
    return users, open_counts, hooks


@admin_router.get("/events")
def list_events(_user: User = Depends(require_permission("SYSTEM_CONFIG", "read"))):
    return [{
        "code": e.code, "module": e.module, "module_label": MODULE_LABELS[e.module], "name": e.name,
        "kind": e.kind, "uses_assets": e.uses_assets, "has_owner": e.has_owner,
        "default_summary": e.describe({}), "check_every_seconds": e.every,
        "params": [{"key": p.key, "label": p.label, "default": p.default, "unit": p.unit, "min": p.min,
                    "max": p.max} for p in e.params],
    } for e in EVENTS.values()]


@admin_router.get("/rules")
def list_rules(_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")), db: Session = Depends(get_db)):
    engine.ensure_default_rules(db)
    users, open_counts, hooks = _rule_context(db)
    rules = db.query(NotificationRule).order_by(NotificationRule.builtin.desc(), NotificationRule.id).all()
    groups = []
    for m in MODULE_ORDER:
        items = [_rule_out(r, users, open_counts, hooks) for r in rules
                 if (EVENTS[r.event_type].module if r.event_type in EVENTS else "system") == m]
        groups.append({"module": m, "label": MODULE_LABELS[m], "rules": items})
    return {"groups": groups}


def _get_rule(db: Session, rule_id: int) -> NotificationRule:
    rule = db.get(NotificationRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


def _close_rule_alerts(db: Session, rule: NotificationRule, user_id: int) -> None:
    for a in db.query(Alert).filter(Alert.rule_id == rule.id, Alert.status.in_(ALERT_OPEN_STATUSES)):
        engine.resolve(db, a, user_id)


@admin_router.get("/rules/{rule_id}")
def get_rule(rule_id: int, _user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
             db: Session = Depends(get_db)):
    users, open_counts, hooks = _rule_context(db)
    return _rule_out(_get_rule(db, rule_id), users, open_counts, hooks)


@admin_router.post("/rules", status_code=201)
def create_rule(data: RuleIn, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                db: Session = Depends(get_db)):
    values = _validate_rule(db, data)
    rule = NotificationRule(**values, builtin=False, updated_by=current_user.id)
    db.add(rule)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.rule.create",
               module="notifications", target_id=rule.id, detail=f"Created rule '{rule.name}' ({rule.event_type})")
    users, open_counts, hooks = _rule_context(db)
    return _rule_out(rule, users, open_counts, hooks)


@admin_router.put("/rules/{rule_id}")
def update_rule(rule_id: int, data: RuleIn,
                current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                db: Session = Depends(get_db)):
    rule = _get_rule(db, rule_id)
    if data.event_type != rule.event_type:
        raise HTTPException(status_code=422, detail="The event of a rule cannot change; create a new rule")
    values = _validate_rule(db, data)
    was_enabled = rule.enabled
    for k, v in values.items():
        setattr(rule, k, v)
    rule.updated_by = current_user.id
    if was_enabled and not rule.enabled:
        _close_rule_alerts(db, rule, current_user.id)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.rule.update",
               module="notifications", target_id=rule.id, detail=f"Updated rule '{rule.name}'")
    users, open_counts, hooks = _rule_context(db)
    return _rule_out(rule, users, open_counts, hooks)


class EnabledIn(BaseModel):
    enabled: bool


@admin_router.patch("/rules/{rule_id}/enabled")
def set_rule_enabled(rule_id: int, data: EnabledIn,
                     current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                     db: Session = Depends(get_db)):
    rule = _get_rule(db, rule_id)
    if rule.enabled and not data.enabled:
        _close_rule_alerts(db, rule, current_user.id)
    rule.enabled = data.enabled
    rule.updated_by = current_user.id
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username,
               action="notification.rule.enable" if data.enabled else "notification.rule.disable",
               module="notifications", target_id=rule.id,
               detail=f"{'Turned on' if data.enabled else 'Turned off'} rule '{rule.name}'")
    users, open_counts, hooks = _rule_context(db)
    return _rule_out(rule, users, open_counts, hooks)


@admin_router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "delete")),
                db: Session = Depends(get_db)):
    rule = _get_rule(db, rule_id)
    if rule.builtin:
        raise HTTPException(status_code=409, detail="Built-in rules can be turned off but not deleted")
    _close_rule_alerts(db, rule, current_user.id)
    name = rule.name
    db.delete(rule)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.rule.delete",
               module="notifications", target_id=rule_id, detail=f"Deleted rule '{name}'")
    return {"success": True}


def _send_now(db: Session, deliveries: List[NotificationDelivery]) -> List[dict]:
    results = []
    for d in deliveries:
        if d.status == "skipped":
            results.append({"channel": d.channel, "recipient": d.recipient, "success": False, "message": d.error})
            continue
        d.attempts = 1
        try:
            engine.deliver(db, d)
        except ch.DeliveryError as exc:
            d.status, d.error = "failed", str(exc)[:1000]
            results.append({"channel": d.channel, "recipient": d.recipient, "success": False, "message": str(exc)})
        else:
            d.status, d.sent_at = "sent", datetime.utcnow()
            results.append({"channel": d.channel, "recipient": d.recipient, "success": True, "message": "Sent"})
        db.commit()
    return results


@admin_router.post("/rules/{rule_id}/test")
def test_rule(rule_id: int, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
              db: Session = Depends(get_db)):
    """Send a sample of this rule's alert to its recipients on its channels, now."""
    rule = _get_rule(db, rule_id)
    if not rule.channels:
        raise HTTPException(status_code=400, detail="The rule has no channel besides in-app")
    event = EVENTS.get(rule.event_type)
    now = datetime.utcnow()
    sample = Alert(id=None, rule_id=rule.id, event_type=rule.event_type, module=event.module if event else "system",
                   severity=rule.severity, fingerprint="test", title=f"Test: {rule.name}",
                   detail="This is a test of the notification rule. No action is needed.",
                   source_label="NGCorion", link="/alerts", status=ALERT_ACTIVE, first_seen_at=now, last_seen_at=now)
    rows = engine.queue_message(db, rule, "test", [sample], now, ch.local_timezone(db))
    if not rows:
        raise HTTPException(status_code=400, detail="Nobody to send to: add recipients with an email or a mobile "
                                                    "number, or a syslog / webhook channel")
    db.flush()
    results = _send_now(db, rows)
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.rule.test",
               module="notifications", target_id=rule.id,
               detail=f"Tested rule '{rule.name}': {sum(r['success'] for r in results)}/{len(results)} sent",
               result="success" if all(r["success"] for r in results) else "failed")
    return {"results": results}


# ===========================================================================
# Notifications: channels and webhooks
# ===========================================================================

def _counts_24h(db: Session) -> Dict[str, Dict[str, int]]:
    since = datetime.utcnow() - timedelta(hours=24)
    out: Dict[str, Dict[str, int]] = {}
    for channel, webhook_id, status, n in (
            db.query(NotificationDelivery.channel, NotificationDelivery.webhook_id, NotificationDelivery.status,
                     func.count())
            .filter(NotificationDelivery.created_at >= since, NotificationDelivery.kind != "test")
            .group_by(NotificationDelivery.channel, NotificationDelivery.webhook_id, NotificationDelivery.status)):
        key = f"webhook:{webhook_id}" if channel == CHANNEL_WEBHOOK else channel
        bucket = out.setdefault(key, {"sent": 0, "failed": 0, "pending": 0, "skipped": 0})
        bucket[status] = bucket.get(status, 0) + n
    return out


def _webhook_out(h: NotificationWebhook, counts: Dict) -> dict:
    return {"id": h.id, "name": h.name, "url": h.url, "enabled": h.enabled,
            "last_success_at": _iso(h.last_success_at), "last_error": h.last_error,
            "last_error_at": _iso(h.last_error_at), "created_at": _iso(h.created_at),
            "stats_24h": counts.get(f"webhook:{h.id}", {"sent": 0, "failed": 0, "pending": 0, "skipped": 0})}


@admin_router.get("/channels")
def get_channels(_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")), db: Session = Depends(get_db)):
    counts = _counts_24h(db)
    empty = {"sent": 0, "failed": 0, "pending": 0, "skipped": 0}
    smtp = ch.load_section(db, SECTION_SMTP)
    sms = ch.load_section(db, SECTION_SMS)
    syslog = ch.load_section(db, SECTION_SYSLOG)
    users_with_phone = db.query(User).filter(User.is_active.is_(True), User.phone.isnot(None), User.phone != "").count()
    since = datetime.utcnow() - timedelta(hours=24)
    return {
        "in_app": {"raised_24h": db.query(Alert).filter(Alert.first_seen_at >= since).count(),
                   "retention_days": engine.RETENTION_DAYS},
        "email": {"configured": bool(smtp.get("host")),
                  "server": f"{smtp.get('host')}:{smtp.get('port') or 587}" if smtp.get("host") else None,
                  "security": "SSL" if smtp.get("use_ssl") else "STARTTLS" if smtp.get("use_tls") else "None",
                  "from": f"{smtp.get('from_name') or 'NGCorion'} <{smtp.get('from_email')}>"
                  if smtp.get("from_email") else None,
                  "stats_24h": counts.get(CHANNEL_EMAIL, empty)},
        "sms": {"configured": bool(sms.get("provider")), "provider": sms.get("provider"),
                "sender": sms.get("sender_number"), "users_with_phone": users_with_phone,
                "stats_24h": counts.get(CHANNEL_SMS, empty)},
        "syslog": {"configured": bool(syslog.get("server_ip")),
                   "target": f"{syslog.get('server_ip')}:{syslog.get('port') or 514}" if syslog.get("server_ip") else None,
                   "protocol": syslog.get("protocol") or "UDP", "facility": syslog.get("facility") or "local0",
                   "format": "CEF over RFC 5424", "stats_24h": counts.get(CHANNEL_SYSLOG, empty)},
        "webhooks": [_webhook_out(h, counts) for h in db.query(NotificationWebhook).order_by(NotificationWebhook.id)],
    }


class ChannelTestIn(BaseModel):
    channel: Literal["email", "sms", "syslog"]
    to: Optional[str] = Field(None, max_length=255)


@admin_router.post("/channels/test")
def test_channel(data: ChannelTestIn, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                 db: Session = Depends(get_db)):
    now = datetime.utcnow()
    to = (data.to or "").strip()
    if data.channel == CHANNEL_EMAIL:
        to = to or (current_user.email or "")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to):
            raise HTTPException(status_code=422, detail="Enter the email address to send the test to")
    elif data.channel == CHANNEL_SMS:
        try:
            to = validate_phone(to or (current_user.phone or "")) or ""
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if not to:
            raise HTTPException(status_code=422, detail="Enter the mobile number to send the test to")
    else:
        to = None
    subject = "[Test] NGCorion notifications"
    body = "This is a test message from NGCorion notifications. If you received it, the channel works.\n"
    d = NotificationDelivery(alert_ids=[], channel=data.channel, recipient=to, kind="test", severity="info",
                             subject=subject, body=body if data.channel != CHANNEL_SMS else "NGCorion test message",
                             payload={"alert_id": 0, "event_type": "test", "module": "system", "severity": "info",
                                      "status": "active", "title": "NGCorion test message", "kind": "test",
                                      "detail": "If this reached your SIEM, the syslog channel works.",
                                      "time_ms": int(now.timestamp() * 1000)},
                             status="pending", created_at=now, next_attempt_at=now)
    db.add(d)
    db.flush()
    result = _send_now(db, [d])[0]
    log_action(db, user_id=current_user.id, username=current_user.username, action=f"notification.test.{data.channel}",
               module="notifications", detail=f"Test {data.channel}{' to ' + to if to else ''}: {result['message']}",
               result="success" if result["success"] else "failed")
    return result


class WebhookIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=8, max_length=500)
    enabled: bool = True
    rotate_secret: bool = False

    @field_validator("name", "url")
    @classmethod
    def _one_line(cls, v: str) -> str:
        v = v.strip()
        if "\n" in v or "\r" in v or not v:
            raise ValueError("must be one line")
        return v


def _check_url(url: str) -> None:
    try:
        ch.check_webhook_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@admin_router.post("/webhooks", status_code=201)
def create_webhook(data: WebhookIn, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                   db: Session = Depends(get_db)):
    _check_url(data.url)
    secret = ch.new_secret()
    hook = NotificationWebhook(name=data.name, url=data.url, enabled=data.enabled,
                               secret_encrypted=encrypt(secret, PURPOSE_NOTIFICATIONS), created_by=current_user.id)
    db.add(hook)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.webhook.create",
               module="notifications", target_id=hook.id, detail=f"Added webhook '{hook.name}'")
    # The secret is shown once, here; afterwards it can only be replaced.
    return {**_webhook_out(hook, {}), "secret": secret}


@admin_router.put("/webhooks/{hook_id}")
def update_webhook(hook_id: int, data: WebhookIn,
                   current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                   db: Session = Depends(get_db)):
    hook = db.get(NotificationWebhook, hook_id)
    if hook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    _check_url(data.url)
    hook.name, hook.url, hook.enabled = data.name, data.url, data.enabled
    secret = None
    if data.rotate_secret:
        secret = ch.new_secret()
        hook.secret_encrypted = encrypt(secret, PURPOSE_NOTIFICATIONS)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.webhook.update",
               module="notifications", target_id=hook.id,
               detail=f"Updated webhook '{hook.name}'" + (" and replaced its secret" if secret else ""))
    out = _webhook_out(hook, _counts_24h(db))
    if secret:
        out["secret"] = secret
    return out


@admin_router.delete("/webhooks/{hook_id}")
def delete_webhook(hook_id: int, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "delete")),
                   db: Session = Depends(get_db)):
    hook = db.get(NotificationWebhook, hook_id)
    if hook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    channel = f"{CHANNEL_WEBHOOK}:{hook.id}"
    for rule in db.query(NotificationRule).all():
        if channel in (rule.channels or []):
            rule.channels = [c for c in rule.channels if c != channel]
    name = hook.name
    db.delete(hook)
    db.commit()
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.webhook.delete",
               module="notifications", target_id=hook_id, detail=f"Deleted webhook '{name}'")
    return {"success": True}


@admin_router.post("/webhooks/{hook_id}/test")
def test_webhook(hook_id: int, current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                 db: Session = Depends(get_db)):
    hook = db.get(NotificationWebhook, hook_id)
    if hook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    now = datetime.utcnow()
    d = NotificationDelivery(alert_ids=[], channel=CHANNEL_WEBHOOK, webhook_id=hook.id, kind="test",
                             severity="info", subject="[Test] NGCorion notifications", body="Test",
                             payload={"kind": "test", "sent_at": now.isoformat() + "Z",
                                      "summary": "NGCorion test message", "alerts": []},
                             status="pending", created_at=now, next_attempt_at=now)
    db.add(d)
    db.flush()
    result = _send_now(db, [d])[0]
    log_action(db, user_id=current_user.id, username=current_user.username, action="notification.webhook.test",
               module="notifications", target_id=hook.id, detail=f"Tested webhook '{hook.name}': {result['message']}",
               result="success" if result["success"] else "failed")
    return result


# ===========================================================================
# Notifications: delivery log and editor options
# ===========================================================================

@admin_router.get("/deliveries")
def list_deliveries(
    channel: Optional[Literal["email", "sms", "syslog", "webhook"]] = None,
    status: Optional[Literal["pending", "sent", "failed", "skipped"]] = None,
    search: Optional[str] = Query(None, max_length=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    _user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
    db: Session = Depends(get_db),
):
    q = db.query(NotificationDelivery)
    if channel:
        q = q.filter(NotificationDelivery.channel == channel)
    if status:
        q = q.filter(NotificationDelivery.status == status)
    if search:
        like = f"%{search.strip()}%"
        q = q.filter(or_(NotificationDelivery.subject.ilike(like), NotificationDelivery.recipient.ilike(like)))
    total = q.count()
    rows = q.order_by(NotificationDelivery.id.desc()).offset(offset).limit(limit).all()
    rules = {r.id: r.name for r in db.query(NotificationRule.id, NotificationRule.name)}
    hooks = {h.id: h.name for h in db.query(NotificationWebhook.id, NotificationWebhook.name)}
    return {"total": total, "items": [{
        "id": d.id, "channel": d.channel, "recipient": d.recipient or (
            hooks.get(d.webhook_id, "deleted webhook") if d.channel == CHANNEL_WEBHOOK else
            "Syslog server" if d.channel == CHANNEL_SYSLOG else None),
        "kind": d.kind, "severity": d.severity, "subject": d.subject, "rule_name": rules.get(d.rule_id),
        "alert_ids": d.alert_ids or [], "status": d.status, "attempts": d.attempts, "error": d.error,
        "created_at": _iso(d.created_at), "sent_at": _iso(d.sent_at),
        "next_attempt_at": _iso(d.next_attempt_at) if d.status == "pending" else None,
    } for d in rows]}


@admin_router.get("/options")
def editor_options(_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")), db: Session = Depends(get_db)):
    return {
        "roles": [{"key": r.value, "label": {"admin": "Admins", "manager": "Managers", "user": "Users",
                                              "guest": "Guests"}[r.value]} for r in UserRole],
        "users": [{"id": u.id, "username": u.username, "email": u.email, "has_phone": bool(u.phone)}
                  for u in db.query(User).filter(User.is_active.is_(True)).order_by(User.username)],
        "asset_types": [{"id": t.id, "name": t.type_name} for t in db.query(AssetType).order_by(AssetType.type_name)],
        "zones": [{"id": z.id, "name": z.name} for z in db.query(RiskZone).order_by(RiskZone.name)],
        "assets": [{"id": a.id, "name": a.asset_name, "ip": a.ip_address}
                   for a in db.query(Asset.id, Asset.asset_name, Asset.ip_address).order_by(Asset.asset_name)],
        "webhooks": [{"id": h.id, "name": h.name, "enabled": h.enabled}
                     for h in db.query(NotificationWebhook).order_by(NotificationWebhook.id)],
    }
