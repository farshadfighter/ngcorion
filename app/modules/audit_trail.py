"""
The security audit trail, for review (FAU_SAR): every row of audit_logs (who did what, to what,
from where, with what result) and of login_logs (every sign-in attempt), searchable, filtered and
paged on the server, and exportable as CSV.

    GET /api/audit-trail/events             audit_logs, newest first
    GET /api/audit-trail/events/facets      the modules, actions and results present (filter lists)
    GET /api/audit-trail/events/export.csv
    GET /api/audit-trail/logins             login_logs, newest first
    GET /api/audit-trail/logins/export.csv

Readable with the System Log permission (LOGS read); administrators always. Reading is not
recorded, exporting is (audit_trail.export, with the filters and the row count): an export is a
copy of the trail leaving the system. CSV cells are protected against formula injection.
The trail itself cannot be changed here or anywhere else (the database trigger on audit_logs).
"""
import csv
import io
from datetime import date, datetime, time, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Query as SAQuery, Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import LoginLog, User
from app.models.security_audit_log import AuditLog, log_action
from app.utils.excel_utils import neutralize_formula

router = APIRouter(prefix="/api/audit-trail", tags=["Audit trail"])

MAX_PAGE_SIZE = 200
MAX_EXPORT_ROWS = 100_000

_reader = require_permission("LOGS", "read")


class AuditEvent(BaseModel):
    id: int
    timestamp: datetime
    username: Optional[str] = None
    action: str
    module: Optional[str] = None
    target_id: Optional[int] = None
    ip_address: Optional[str] = None
    result: str
    detail: Optional[str] = None


class LoginEvent(BaseModel):
    id: int
    timestamp: datetime
    username: str
    success: bool
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    message: Optional[str] = None


class EventPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AuditEvent]


class LoginPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[LoginEvent]


class Facets(BaseModel):
    modules: List[str]
    actions: List[str]
    results: List[str]


def _like(text: str) -> str:
    """A LIKE pattern matching `text` anywhere, with LIKE's own wildcards taken literally."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _period(query: SAQuery, column, date_from: Optional[date], date_to: Optional[date]) -> SAQuery:
    """Limit to whole days, both ends included (UTC)."""
    if date_from:
        query = query.filter(column >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        query = query.filter(column < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc))
    return query


def _events(db: Session, q, module, action, result, username, ip, date_from, date_to) -> SAQuery:
    query = db.query(AuditLog)
    if q:
        pattern = _like(q.strip())
        query = query.filter(or_(AuditLog.action.ilike(pattern, escape="\\"),
                                 AuditLog.username.ilike(pattern, escape="\\"),
                                 AuditLog.module.ilike(pattern, escape="\\"),
                                 AuditLog.detail.ilike(pattern, escape="\\")))
    if module:
        query = query.filter(AuditLog.module == module)
    if action:
        query = query.filter(AuditLog.action == action)
    if result:
        query = query.filter(AuditLog.result == result)
    if username:
        query = query.filter(AuditLog.username.ilike(_like(username.strip()), escape="\\"))
    if ip:
        query = query.filter(AuditLog.ip_address.ilike(_like(ip.strip()), escape="\\"))
    return _period(query, AuditLog.timestamp, date_from, date_to)


def _logins(db: Session, username, success, ip, date_from, date_to) -> SAQuery:
    query = db.query(LoginLog)
    if username:
        query = query.filter(LoginLog.username.ilike(_like(username.strip()), escape="\\"))
    if success is not None:
        query = query.filter(LoginLog.success == success)
    if ip:
        query = query.filter(LoginLog.ip_address.ilike(_like(ip.strip()), escape="\\"))
    return _period(query, LoginLog.timestamp, date_from, date_to)


# Filters shared by the list and the export of each kind.
def event_filters(
    q: Optional[str] = Query(None, max_length=200, description="Text in the action, user, module or detail"),
    module: Optional[str] = Query(None, max_length=50),
    action: Optional[str] = Query(None, max_length=100),
    result: Optional[str] = Query(None, max_length=20),
    username: Optional[str] = Query(None, max_length=100),
    ip: Optional[str] = Query(None, max_length=64),
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
) -> dict:
    return dict(q=q, module=module, action=action, result=result, username=username, ip=ip,
                date_from=date_from, date_to=date_to)


def login_filters(
    username: Optional[str] = Query(None, max_length=100),
    success: Optional[bool] = None,
    ip: Optional[str] = Query(None, max_length=64),
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
) -> dict:
    return dict(username=username, success=success, ip=ip, date_from=date_from, date_to=date_to)


@router.get("/events", response_model=EventPage)
def list_events(filters: dict = Depends(event_filters), page: int = Query(1, ge=1),
                page_size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
                db: Session = Depends(get_db), _user: User = Depends(_reader)):
    query = _events(db, **filters)
    total = query.count()
    rows = (query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .offset((page - 1) * page_size).limit(page_size).all())
    return EventPage(total=total, page=page, page_size=page_size,
                     items=[AuditEvent.model_validate(r, from_attributes=True) for r in rows])


@router.get("/events/facets", response_model=Facets)
def event_facets(db: Session = Depends(get_db), _user: User = Depends(_reader)):
    def distinct(column):
        return sorted(v for (v,) in db.query(column).filter(column.isnot(None)).distinct().limit(1000) if v)
    return Facets(modules=distinct(AuditLog.module), actions=distinct(AuditLog.action),
                  results=distinct(AuditLog.result))


@router.get("/logins", response_model=LoginPage)
def list_logins(filters: dict = Depends(login_filters), page: int = Query(1, ge=1),
                page_size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
                db: Session = Depends(get_db), _user: User = Depends(_reader)):
    query = _logins(db, **filters)
    total = query.count()
    rows = (query.order_by(LoginLog.timestamp.desc(), LoginLog.id.desc())
            .offset((page - 1) * page_size).limit(page_size).all())
    return LoginPage(total=total, page=page, page_size=page_size,
                     items=[LoginEvent.model_validate(r, from_attributes=True) for r in rows])


def _csv(header: List[str], rows) -> io.StringIO:
    out = io.StringIO()
    out.write("﻿")  # BOM: Excel opens UTF-8 (Persian text) correctly
    writer = csv.writer(out)
    writer.writerow(header)
    for row in rows:
        writer.writerow([neutralize_formula("" if v is None else (v.isoformat() if isinstance(v, datetime) else v))
                         for v in row])
    out.seek(0)
    return out


def _record_export(db: Session, user: User, request: Request, kind: str, filters: dict, rows: int) -> None:
    used = ", ".join(f"{k}={v.isoformat() if isinstance(v, date) else v}"
                     for k, v in filters.items() if v not in (None, ""))
    log_action(db, user_id=user.id, username=user.username, action="audit_trail.export", module="logs",
               ip_address=request.client.host if request.client else None,
               detail=(f"Exported {rows} security events; filters: {used or 'none'}" if kind == "events"
                       else f"Exported {rows} sign-ins; filters: {used or 'none'}"))


def _download(content: io.StringIO, name: str) -> Response:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(content.getvalue().encode("utf-8"), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}-{stamp}.csv"'})


@router.get("/events/export.csv")
def export_events(request: Request, filters: dict = Depends(event_filters),
                  db: Session = Depends(get_db), user: User = Depends(_reader)):
    rows = (_events(db, **filters).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .limit(MAX_EXPORT_ROWS).all())
    content = _csv(["id", "time_utc", "user", "action", "module", "target_id", "address", "result", "detail"],
                   ((r.id, r.timestamp, r.username, r.action, r.module, r.target_id, r.ip_address, r.result,
                     r.detail) for r in rows))
    _record_export(db, user, request, "events", filters, len(rows))
    return _download(content, "ngcorion-audit-trail")


@router.get("/logins/export.csv")
def export_logins(request: Request, filters: dict = Depends(login_filters),
                  db: Session = Depends(get_db), user: User = Depends(_reader)):
    rows = (_logins(db, **filters).order_by(LoginLog.timestamp.desc(), LoginLog.id.desc())
            .limit(MAX_EXPORT_ROWS).all())
    content = _csv(["id", "time_utc", "user", "success", "address", "user_agent", "message"],
                   ((r.id, r.timestamp, r.username, "yes" if r.success else "no", r.ip_address, r.user_agent,
                     r.message) for r in rows))
    _record_export(db, user, request, "sign-ins", filters, len(rows))
    return _download(content, "ngcorion-sign-ins")
