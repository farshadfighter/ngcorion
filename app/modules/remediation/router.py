"""
/api/remediation - remediation tracking and risk acceptance.

Reading needs the REMEDIATION module's read permission; changing an item or
requesting a risk acceptance needs write. Approving or rejecting an
acceptance is limited by role (administrator or manager, never the
requester, critical/known-exploited only by an administrator) - see
service.can_decide. Deadline settings need SYSTEM_CONFIG write.
"""
from datetime import date, datetime, time, timedelta
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, log_action
from app.models.remediation import (ACCEPT_APPROVED, ACCEPT_EXPIRED, ACCEPT_PENDING, ACCEPT_REJECTED,
                                    ACCEPT_REVOKED, ITEM_ACCEPTED, ITEM_ACTIVE, ITEM_IN_PROGRESS, ITEM_OPEN,
                                    ITEM_PENDING, ITEM_RESOLVED, SCOPE_ITEM, SCOPE_REF, SEVERITIES,
                                    RemediationEvent, RemediationItem, RiskAcceptance)
from app.modules.remediation import service
from app.modules.remediation.service import RemediationError

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])

_read = require_permission("REMEDIATION", "read")
_write = require_permission("REMEDIATION", "write")
MODULE = "remediation"
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _fail(e: RemediationError):
    raise HTTPException(status_code=e.status_code, detail=e.message)


def _names(db: Session, ids) -> Dict[int, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return dict(db.query(User.id, User.username).filter(User.id.in_(ids)).all())


def _item_out(i: RemediationItem, names: Dict[int, str], acc: Optional[RiskAcceptance], now: datetime) -> dict:
    return {
        "id": i.id, "source": i.source, "ref": i.ref, "asset_id": i.asset_id, "asset_name": i.asset_name,
        "ip_address": i.ip_address, "title": i.title, "detail": i.detail or {}, "severity": i.severity,
        "kev": i.kev, "status": i.status, "owner_id": i.owner_id, "owner": names.get(i.owner_id),
        "due_at": _iso(i.due_at), "due_custom": i.due_custom,
        "overdue": bool(i.status in ITEM_ACTIVE and i.due_at and i.due_at < now),
        "first_seen_at": _iso(i.first_seen_at), "last_seen_at": _iso(i.last_seen_at),
        "resolved_at": _iso(i.resolved_at), "closed_reason": i.closed_reason, "reopened": i.reopened,
        "acceptance": ({"id": acc.id, "expires_at": _iso(acc.expires_at), "scope": acc.scope} if acc else None),
    }


def _acceptance_out(a: RiskAcceptance, names: Dict[int, str], user: User, now: datetime,
                    items_count: Optional[int] = None) -> dict:
    status = a.status
    if status == ACCEPT_APPROVED and a.expires_at <= now:
        status = ACCEPT_EXPIRED
    blocked = service.can_decide(user, a) if a.status == ACCEPT_PENDING else "decided"
    return {
        "id": a.id, "scope": a.scope, "source": a.source, "ref": a.ref, "item_id": a.item_id,
        "asset_id": a.asset_id, "title": a.title, "severity": a.severity, "kev": a.kev,
        "justification": a.justification, "compensating_control": a.compensating_control,
        "expires_at": _iso(a.expires_at), "status": status,
        "expiring": bool(status == ACCEPT_APPROVED and a.expires_at < now + timedelta(days=7)),
        "requested_by": names.get(a.requested_by), "requested_by_id": a.requested_by,
        "requested_at": _iso(a.requested_at),
        "decided_by": names.get(a.decided_by), "decided_at": _iso(a.decided_at), "decision_note": a.decision_note,
        "ended_by": names.get(a.ended_by), "ended_at": _iso(a.ended_at),
        "can_decide": blocked is None, "decide_blocked": None if blocked in (None, "decided") else blocked,
        "can_withdraw": service.can_withdraw(user, a),
        "items": items_count,
    }


# ── summary and items ─────────────────────────────────────────────────────

@router.get("/summary")
def get_summary(_user: User = Depends(_read), db: Session = Depends(get_db)):
    return service.summary(db)


@router.get("/items")
def list_items(
    view: Literal["open", "overdue", "in_progress", "pending_verification", "accepted", "resolved",
                  "unassigned", "mine", "all"] = "open",
    source: Optional[Literal["cve", "audit", "arch"]] = None,
    severity: Optional[Literal["critical", "high", "medium", "low"]] = None,
    asset_id: Optional[int] = None,
    q: Optional[str] = Query(None, max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(_read),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    query = db.query(RemediationItem)
    active = RemediationItem.status.in_(ITEM_ACTIVE)
    if view == "open":
        query = query.filter(active)
    elif view == "overdue":
        query = query.filter(active, RemediationItem.due_at < now)
    elif view == "unassigned":
        query = query.filter(active, RemediationItem.owner_id.is_(None))
    elif view == "mine":
        query = query.filter(active, RemediationItem.owner_id == user.id)
    elif view != "all":
        query = query.filter(RemediationItem.status == view)
    if source:
        query = query.filter(RemediationItem.source == source)
    if severity:
        query = query.filter(RemediationItem.severity == severity)
    if asset_id:
        query = query.filter(RemediationItem.asset_id == asset_id)
    if q and q.strip():
        like = f"%{q.strip()}%"
        query = query.filter(or_(RemediationItem.title.ilike(like), RemediationItem.ref.ilike(like),
                                 RemediationItem.asset_name.ilike(like), RemediationItem.ip_address.ilike(like)))
    rows = query.all()
    if view == "resolved":
        rows.sort(key=lambda i: i.resolved_at or now, reverse=True)
    else:
        # Most urgent first: overdue, then by deadline, severity and KEV.
        rows.sort(key=lambda i: (0 if i.due_at and i.due_at < now else 1, i.due_at or datetime.max,
                                 SEVERITY_ORDER.get(i.severity, 9), not i.kev, i.id))
    total = len(rows)
    page = rows[offset:offset + limit]
    accs = {a.id: a for a in db.query(RiskAcceptance).filter(
        RiskAcceptance.id.in_([i.acceptance_id for i in page if i.acceptance_id]))} if page else {}
    names = _names(db, [i.owner_id for i in page])
    return {"total": total, "offset": offset, "limit": limit,
            "items": [_item_out(i, names, accs.get(i.acceptance_id), now) for i in page]}


@router.get("/items/{item_id}")
def get_item(item_id: int, user: User = Depends(_read), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    item = db.get(RemediationItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    events = (db.query(RemediationEvent).filter(RemediationEvent.item_id == item.id)
              .order_by(RemediationEvent.at, RemediationEvent.id).all())
    accs = (db.query(RiskAcceptance)
            .filter(or_(RiskAcceptance.item_id == item.id,
                        (RiskAcceptance.scope == SCOPE_REF) & (RiskAcceptance.source == item.source)
                        & (RiskAcceptance.ref == item.ref)))
            .order_by(RiskAcceptance.requested_at.desc()).all())
    user_ids = [item.owner_id] + [e.user_id for e in events] + [(e.data or {}).get("owner_id") for e in events]
    user_ids += [x for a in accs for x in (a.requested_by, a.decided_by, a.ended_by)]
    names = _names(db, user_ids)
    current = next((a for a in accs if a.id == item.acceptance_id), None)
    out = _item_out(item, names, current, now)
    out["events"] = [{"at": _iso(e.at), "kind": e.kind, "user": names.get(e.user_id),
                      "data": {**(e.data or {}), **({"owner": names.get((e.data or {}).get("owner_id"))}
                                                    if (e.data or {}).get("owner_id") else {})}}
                     for e in events]
    out["acceptances"] = [_acceptance_out(a, names, user, now) for a in accs]
    settings = service.get_settings(db)
    out["accept_max_days"] = service.accept_max_days(item.severity, item.kev, settings)
    return out


class ItemUpdate(BaseModel):
    owner_id: Optional[int] = None
    due_date: Optional[date] = None          # null resets the deadline to the SLA
    status: Optional[Literal["open", "in_progress", "pending_verification"]] = None
    note: Optional[str] = Field(None, max_length=2000)


@router.patch("/items/{item_id}")
def update_item(item_id: int, data: ItemUpdate, user: User = Depends(_write), db: Session = Depends(get_db)):
    item = db.get(RemediationItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    sent = data.model_fields_set
    kwargs = {}
    if "owner_id" in sent:
        kwargs["owner_id"] = data.owner_id
    if "due_date" in sent:
        kwargs["due_at"] = datetime.combine(data.due_date, time(23, 59)) if data.due_date else None
    try:
        service.update_item(db, item, user, status=data.status, note=data.note, **kwargs)
    except RemediationError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="remediation.item.update", module=MODULE,
               target_id=item.id, detail=f"{item.ref} on {item.asset_name}: {', '.join(sorted(sent)) or 'nothing'}")
    return get_item(item_id, user, db)


@router.post("/sync")
def sync_now(user: User = Depends(_write), db: Session = Depends(get_db)):
    return {"stats": service.sync(db), "summary": service.summary(db)}


@router.get("/users")
def list_users(_user: User = Depends(_read), db: Session = Depends(get_db)):
    """People a finding can be assigned to."""
    return [{"id": u.id, "username": u.username, "role": u.role.value}
            for u in db.query(User).filter(User.is_active.is_(True)).order_by(User.username)]


# ── risk acceptance ───────────────────────────────────────────────────────

class AcceptanceRequest(BaseModel):
    scope: Literal["item", "ref"] = "item"
    justification: str = Field(..., min_length=10, max_length=4000)
    compensating_control: Optional[str] = Field(None, max_length=4000)
    expires_on: date


@router.post("/items/{item_id}/acceptances", status_code=201)
def request_acceptance(item_id: int, data: AcceptanceRequest, user: User = Depends(_write),
                       db: Session = Depends(get_db)):
    item = db.get(RemediationItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        acc = service.request_acceptance(
            db, item, user, scope=data.scope, justification=data.justification,
            compensating_control=data.compensating_control,
            expires_at=datetime.combine(data.expires_on, time(23, 59)))
    except RemediationError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="remediation.acceptance.request",
               module=MODULE, target_id=acc.id,
               detail=f"{acc.ref} ({'every asset' if acc.scope == SCOPE_REF else item.asset_name}) "
                      f"until {acc.expires_at:%Y-%m-%d}")
    return _acceptance_out(acc, _names(db, [acc.requested_by]), user, datetime.utcnow())


@router.get("/acceptances")
def list_acceptances(
    view: Literal["pending", "active", "expiring", "ended", "rejected", "all"] = "pending",
    user: User = Depends(_read),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    q = db.query(RiskAcceptance)
    approved_live = (RiskAcceptance.status == ACCEPT_APPROVED) & (RiskAcceptance.expires_at > now)
    if view == "pending":
        q = q.filter(RiskAcceptance.status == ACCEPT_PENDING)
    elif view == "active":
        q = q.filter(approved_live)
    elif view == "expiring":
        q = q.filter(approved_live, RiskAcceptance.expires_at < now + timedelta(days=7))
    elif view == "ended":
        q = q.filter(or_(RiskAcceptance.status.in_((ACCEPT_EXPIRED, ACCEPT_REVOKED)),
                         (RiskAcceptance.status == ACCEPT_APPROVED) & (RiskAcceptance.expires_at <= now)))
    elif view == "rejected":
        q = q.filter(RiskAcceptance.status == ACCEPT_REJECTED)
    rows = q.order_by(RiskAcceptance.requested_at.desc()).limit(500).all()
    names = _names(db, [x for a in rows for x in (a.requested_by, a.decided_by, a.ended_by)])
    counts = {}
    for a in rows:
        if a.scope == SCOPE_REF:
            counts[a.id] = db.query(RemediationItem).filter(
                RemediationItem.source == a.source, RemediationItem.ref == a.ref,
                RemediationItem.status != ITEM_RESOLVED).count()
    assets = dict(db.query(RemediationItem.id, RemediationItem.asset_name).filter(
        RemediationItem.id.in_([a.item_id for a in rows if a.item_id])).all()) if rows else {}
    all_q = db.query(RiskAcceptance)
    return {
        "counts": {
            "pending": all_q.filter(RiskAcceptance.status == ACCEPT_PENDING).count(),
            "active": all_q.filter(approved_live).count(),
            "expiring": all_q.filter(approved_live, RiskAcceptance.expires_at < now + timedelta(days=7)).count(),
            "ended": all_q.filter(or_(RiskAcceptance.status.in_((ACCEPT_EXPIRED, ACCEPT_REVOKED)),
                                      (RiskAcceptance.status == ACCEPT_APPROVED)
                                      & (RiskAcceptance.expires_at <= now))).count(),
            "rejected": all_q.filter(RiskAcceptance.status == ACCEPT_REJECTED).count(),
        },
        "items": [{**_acceptance_out(a, names, user, now, counts.get(a.id)),
                   "asset_name": assets.get(a.item_id)} for a in rows],
    }


class Decision(BaseModel):
    note: Optional[str] = Field(None, max_length=2000)


def _get_acceptance(db: Session, acceptance_id: int) -> RiskAcceptance:
    acc = db.get(RiskAcceptance, acceptance_id)
    if acc is None:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    return acc


@router.post("/acceptances/{acceptance_id}/approve")
def approve(acceptance_id: int, data: Optional[Decision] = None, user: User = Depends(_read), db: Session = Depends(get_db)):
    acc = _get_acceptance(db, acceptance_id)
    try:
        service.decide_acceptance(db, acc, user, True, data.note if data else None)
    except RemediationError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="remediation.acceptance.approve",
               module=MODULE, target_id=acc.id, detail=f"{acc.ref} until {acc.expires_at:%Y-%m-%d}")
    return _acceptance_out(acc, _names(db, [acc.requested_by, acc.decided_by]), user, datetime.utcnow())


@router.post("/acceptances/{acceptance_id}/reject")
def reject(acceptance_id: int, data: Decision, user: User = Depends(_read), db: Session = Depends(get_db)):
    acc = _get_acceptance(db, acceptance_id)
    try:
        service.decide_acceptance(db, acc, user, False, data.note)
    except RemediationError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="remediation.acceptance.reject",
               module=MODULE, target_id=acc.id, detail=f"{acc.ref}: {data.note or 'no reason given'}")
    return _acceptance_out(acc, _names(db, [acc.requested_by, acc.decided_by]), user, datetime.utcnow())


@router.post("/acceptances/{acceptance_id}/withdraw")
def withdraw(acceptance_id: int, user: User = Depends(_read), db: Session = Depends(get_db)):
    acc = _get_acceptance(db, acceptance_id)
    try:
        service.end_acceptance(db, acc, user)
    except RemediationError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="remediation.acceptance.withdraw",
               module=MODULE, target_id=acc.id, detail=acc.ref)
    return _acceptance_out(acc, _names(db, [acc.requested_by, acc.decided_by, acc.ended_by]), user,
                           datetime.utcnow())


# ── deadlines ─────────────────────────────────────────────────────────────

class Days(BaseModel):
    kev: int = Field(..., ge=1, le=3650)
    critical: int = Field(..., ge=1, le=3650)
    high: int = Field(..., ge=1, le=3650)
    medium: int = Field(..., ge=1, le=3650)
    low: int = Field(..., ge=1, le=3650)


class RemediationSettings(BaseModel):
    sla: Days
    accept_max: Days


@router.get("/settings")
def get_settings(_user: User = Depends(_read), db: Session = Depends(get_db)):
    return service.get_settings(db)


@router.put("/settings")
def put_settings(data: RemediationSettings, user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                 db: Session = Depends(get_db)):
    saved = service.save_settings(db, data.model_dump(), user)
    log_action(db, user_id=user.id, username=user.username, action="remediation.settings.update",
               module=MODULE, detail=f"Deadlines {saved['sla']}, longest acceptance {saved['accept_max']}")
    return saved
