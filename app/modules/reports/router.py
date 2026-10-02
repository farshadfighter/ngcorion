"""
/api/reports - report catalog, building, archive, verification and schedules.

The REPORTS permission module: read to see the catalog and your own reports
and download them, write to build and schedule, delete to remove reports.
Every section of a report also needs read access to the module it comes
from (checked when the report is built). Administrators see every report
and schedule. Report settings (organization name, logo, retention) need
SYSTEM_CONFIG write.
"""
from datetime import datetime
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, log_action
from app.models.report import REPORT_FAILED, REPORT_PENDING, REPORT_READY, Report, ReportFile, ReportSchedule
from app.modules.reports import scope as scope_mod
from app.modules.reports import service
from app.modules.reports.service import ReportError
from app.modules.reports.templates import GROUPS, PLANNED, TEMPLATES

router = APIRouter(prefix="/api/reports", tags=["Reports"])

_read = require_permission("REPORTS", "read")
_write = require_permission("REPORTS", "write")
_delete = require_permission("REPORTS", "delete")
MODULE = "reports"
MAX_VERIFY_BYTES = 50 * 1024 * 1024


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _fail(e: ReportError):
    raise HTTPException(status_code=e.status_code, detail=e.message)


def _names(db: Session, ids) -> Dict[int, str]:
    ids = {i for i in ids if i}
    return dict(db.query(User.id, User.username).filter(User.id.in_(ids)).all()) if ids else {}


def _report_out(r: Report, files: List[ReportFile], names: Dict[int, str], schedules: Dict[int, str]) -> dict:
    return {
        "id": r.id, "code": r.code, "template": r.template, "title": r.title, "language": r.language,
        "formats": r.formats, "classification": r.classification, "params": r.params,
        "period_start": _iso(r.period_start), "period_end": _iso(r.period_end), "status": r.status,
        "progress": r.progress, "error": r.error, "omitted": r.omitted or [], "page_count": r.page_count,
        "pinned": r.pinned, "created_by": names.get(r.created_by), "schedule_id": r.schedule_id,
        "schedule": schedules.get(r.schedule_id), "created_at": _iso(r.created_at), "started_at": _iso(r.started_at),
        "finished_at": _iso(r.finished_at), "delivered_to": r.delivered_to or [], "delivery_error": r.delivery_error,
        "files": [{"kind": f.kind, "filename": f.filename, "size": f.size, "sha256": f.sha256} for f in files],
    }


def _reports_out(db: Session, rows: List[Report]) -> List[dict]:
    ids = [r.id for r in rows]
    files: Dict[int, list] = {}
    if ids:
        for f in (db.query(ReportFile.id, ReportFile.report_id, ReportFile.kind, ReportFile.filename, ReportFile.size,
                           ReportFile.sha256).filter(ReportFile.report_id.in_(ids)).order_by(ReportFile.kind)):
            files.setdefault(f.report_id, []).append(f)
    names = _names(db, [r.created_by for r in rows])
    sched_ids = {r.schedule_id for r in rows if r.schedule_id}
    schedules = dict(db.query(ReportSchedule.id, ReportSchedule.name).filter(ReportSchedule.id.in_(sched_ids))) \
        if sched_ids else {}
    return [_report_out(r, files.get(r.id, []), names, schedules) for r in rows]


# ── catalog ──────────────────────────────────────────────────────────────

def _template_out(db: Session, user: User, t, last: Dict[str, datetime]) -> dict:
    return {
        "id": t.id, "title": t.title, "description": t.description, "group": t.group, "available": t.available,
        "default_period": t.default_period, "last_built": _iso(last.get(t.id)),
        "sections": [{"key": s.key, "title": s.title, "hint": s.hint, "default": s.default,
                      "excel_only": s.excel_only, "allowed": service.can_read(db, user, s.module)}
                     for s in t.sections],
        "options": [{"key": o.key, "label": o.label, "kind": o.kind, "default": o.default,
                     "choices": [{"value": v, "label": l} for v, l in o.choices]} for o in t.options],
    }


@router.get("/catalog")
def catalog(user: User = Depends(_read), db: Session = Depends(get_db)):
    q = service.visible_reports(db, user)
    last = dict(q.with_entities(Report.template, func.max(Report.finished_at))
                .filter(Report.status == REPORT_READY).group_by(Report.template).all())
    templates = [t for t in list(TEMPLATES.values()) + list(PLANNED) if service.template_visible(db, user, t)
                 or not t.available]
    recent = q.order_by(Report.created_at.desc()).limit(3).all()
    return {"groups": [{"id": g, "title": title} for g, title in GROUPS],
            "templates": [_template_out(db, user, t, last) for t in templates],
            "recent": _reports_out(db, recent),
            "default_classification": service.get_settings(db)["default_classification"]}


@router.get("/scope-options")
def scope_options(_user: User = Depends(_read), db: Session = Depends(get_db)):
    return scope_mod.options(db)


# ── building ─────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    template: str = Field(..., max_length=40)
    title: Optional[str] = Field(None, max_length=200)
    language: Literal["fa", "en"] = "fa"
    formats: List[Literal["pdf", "xlsx"]] = ["pdf"]
    classification: Literal["public", "internal", "confidential"] = "internal"
    params: Dict = {}


@router.post("")
def create_report(data: ReportRequest, user: User = Depends(_write), db: Session = Depends(get_db)):
    try:
        r = service.create(db, user, data.template, data.title, data.language, data.formats, data.classification,
                           data.params)
    except ReportError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="reports.create", module=MODULE,
               target_id=r.id, detail=f"{r.code} {r.template}")
    return _reports_out(db, [r])[0]


@router.post("/preview")
def preview(data: ReportRequest, user: User = Depends(_write), db: Session = Depends(get_db)):
    """Build the PDF now without keeping it, so the person can check it before building for real."""
    try:
        template, formats, params = service.validate(db, user, data.template, data.language, ["pdf"],
                                                     data.classification, data.params)
        r = Report(id=0, code="PREVIEW", template=template, title=(data.title or "").strip() or template,
                   language=data.language, formats=["pdf"], classification=data.classification, params=params,
                   created_by=user.id, created_at=datetime.utcnow())
        out = service.build(db, r)
    except ReportError as e:
        db.rollback()
        _fail(e)
    db.rollback()
    filename, content = out["files"]["pdf"]
    return Response(content, media_type="application/pdf", headers={"Content-Disposition": 'inline; filename="preview.pdf"'})


# ── archive ──────────────────────────────────────────────────────────────

VIEWS = ("all", "mine", "scheduled", "running", "failed", "pinned")


def _view(q, view: str, user: User):
    if view == "mine":
        return q.filter(Report.created_by == user.id, Report.schedule_id.is_(None))
    if view == "scheduled":
        return q.filter(Report.schedule_id.isnot(None))
    if view == "running":
        return q.filter(Report.status.in_(REPORT_PENDING))
    if view == "failed":
        return q.filter(Report.status == REPORT_FAILED)
    if view == "pinned":
        return q.filter(Report.pinned.is_(True))
    return q


@router.get("")
def list_reports(view: str = Query("all"), q: Optional[str] = Query(None, max_length=100),
                 offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                 user: User = Depends(_read), db: Session = Depends(get_db)):
    if view not in VIEWS:
        raise HTTPException(status_code=400, detail="Unknown view")
    base = service.visible_reports(db, user)
    counts = {v: _view(base, v, user).count() for v in VIEWS}
    rows = _view(base, view, user)
    if q:
        like = f"%{q.strip()}%"
        rows = rows.filter(or_(Report.title.ilike(like), Report.code.ilike(like)))
    total = rows.count()
    rows = rows.order_by(Report.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "counts": counts, "items": _reports_out(db, rows)}


def _get(db: Session, user: User, report_id: int) -> Report:
    try:
        return service.get_visible(db, user, report_id)
    except ReportError as e:
        _fail(e)


@router.get("/{report_id}")
def get_report(report_id: int, user: User = Depends(_read), db: Session = Depends(get_db)):
    return _reports_out(db, [_get(db, user, report_id)])[0]


@router.get("/{report_id}/files/{kind}")
def download(report_id: int, kind: Literal["pdf", "xlsx"], user: User = Depends(_read),
             db: Session = Depends(get_db)):
    r = _get(db, user, report_id)
    f = db.query(ReportFile).filter(ReportFile.report_id == r.id, ReportFile.kind == kind).first()
    if f is None:
        raise HTTPException(status_code=404, detail="This report has no such file")
    log_action(db, user_id=user.id, username=user.username, action="reports.download", module=MODULE,
               target_id=r.id, detail=f"{r.code} {kind}")
    return Response(f.content, media_type=service.MIME[kind],
                    headers={"Content-Disposition": f'attachment; filename="{f.filename}"',
                             "X-Content-SHA256": f.sha256})


@router.post("/{report_id}/rerun")
def rerun(report_id: int, user: User = Depends(_write), db: Session = Depends(get_db)):
    old = _get(db, user, report_id)
    try:
        r = service.create(db, user, old.template, old.title, old.language, old.formats, old.classification,
                           old.params)
    except ReportError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="reports.rerun", module=MODULE,
               target_id=r.id, detail=f"{r.code} from {old.code}")
    return _reports_out(db, [r])[0]


class PinRequest(BaseModel):
    pinned: bool


@router.post("/{report_id}/pin")
def pin(report_id: int, data: PinRequest, user: User = Depends(_write), db: Session = Depends(get_db)):
    r = _get(db, user, report_id)
    r.pinned = data.pinned
    db.commit()
    return _reports_out(db, [r])[0]


@router.post("/{report_id}/cancel")
def cancel(report_id: int, user: User = Depends(_write), db: Session = Depends(get_db)):
    r = _get(db, user, report_id)
    try:
        service.cancel(db, r)
    except ReportError as e:
        _fail(e)
    return _reports_out(db, [r])[0]


@router.delete("/{report_id}")
def delete_report(report_id: int, user: User = Depends(_delete), db: Session = Depends(get_db)):
    r = _get(db, user, report_id)
    if r.status in REPORT_PENDING:
        raise HTTPException(status_code=409, detail="Wait for the report to finish, or cancel it")
    code = r.code
    db.delete(r)
    db.commit()
    log_action(db, user_id=user.id, username=user.username, action="reports.delete", module=MODULE,
               target_id=report_id, detail=code)
    return {"deleted": report_id}


@router.post("/verify")
async def verify(file: UploadFile = File(...), user: User = Depends(_read), db: Session = Depends(get_db)):
    content = await file.read(MAX_VERIFY_BYTES + 1)
    if len(content) > MAX_VERIFY_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
    found = service.verify(db, content)
    log_action(db, user_id=user.id, username=user.username, action="reports.verify", module=MODULE,
               detail=f"{file.filename}: {'match' if found else 'no match'}")
    if not found:
        return {"match": False}
    f, r = found
    return {"match": True, "kind": f.kind, "sha256": f.sha256, "code": r.code, "title": r.title,
            "created_at": _iso(r.created_at), "created_by": _names(db, [r.created_by]).get(r.created_by)}


# ── schedules ────────────────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    name: str = Field(..., max_length=200)
    template: str = Field(..., max_length=40)
    title: Optional[str] = Field(None, max_length=200)
    language: Literal["fa", "en"] = "fa"
    formats: List[Literal["pdf", "xlsx"]] = ["pdf"]
    classification: Literal["public", "internal", "confidential"] = "internal"
    params: Dict = {}
    frequency: Literal["daily", "weekly", "monthly", "quarterly"] = "monthly"
    weekday: Optional[int] = None
    monthday: Optional[int] = None
    run_time: str = Field("08:00", max_length=5)
    recipient_users: List[int] = []
    recipient_emails: List[str] = []
    attach: bool = True
    enabled: bool = True


def _schedule_out(s: ReportSchedule, names: Dict[int, str]) -> dict:
    return {
        "id": s.id, "name": s.name, "template": s.template, "title": s.title, "language": s.language,
        "formats": s.formats, "classification": s.classification, "params": s.params, "frequency": s.frequency,
        "weekday": s.weekday, "monthday": s.monthday, "run_time": s.run_time,
        "recipient_users": s.recipient_users or [], "recipient_emails": s.recipient_emails or [],
        "recipient_names": [names.get(u) for u in s.recipient_users or [] if names.get(u)],
        "attach": s.attach, "enabled": s.enabled, "owner": names.get(s.owner_id), "owner_id": s.owner_id,
        "next_run_at": _iso(s.next_run_at), "last_run_at": _iso(s.last_run_at), "last_status": s.last_status,
        "last_error": s.last_error, "last_report_id": s.last_report_id,
    }


def _schedules_out(db: Session, rows: List[ReportSchedule]) -> List[dict]:
    names = _names(db, [s.owner_id for s in rows] + [u for s in rows for u in (s.recipient_users or [])])
    return [_schedule_out(s, names) for s in rows]


def _own_schedule(db: Session, user: User, schedule_id: int) -> ReportSchedule:
    s = db.get(ReportSchedule, schedule_id)
    if s is None or (s.owner_id != user.id and service._role(user) != "admin"):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return s


@router.get("/schedules/list")
def list_schedules(user: User = Depends(_read), db: Session = Depends(get_db)):
    q = db.query(ReportSchedule)
    if service._role(user) != "admin":
        q = q.filter(ReportSchedule.owner_id == user.id)
    return _schedules_out(db, q.order_by(ReportSchedule.name).all())


@router.get("/schedules/recipients")
def recipient_options(_user: User = Depends(_read), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.is_active.is_(True)).order_by(User.username).all()
    return [{"id": u.id, "username": u.username, "has_email": bool(u.email)} for u in users]


@router.post("/schedules")
def create_schedule(data: ScheduleRequest, user: User = Depends(_write), db: Session = Depends(get_db)):
    try:
        s = service.save_schedule(db, user, data.model_dump())
    except ReportError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="reports.schedule.create", module=MODULE,
               target_id=s.id, detail=s.name)
    return _schedules_out(db, [s])[0]


@router.put("/schedules/{schedule_id}")
def update_schedule(schedule_id: int, data: ScheduleRequest, user: User = Depends(_write),
                    db: Session = Depends(get_db)):
    s = _own_schedule(db, user, schedule_id)
    owner = db.get(User, s.owner_id) or user
    try:
        s = service.save_schedule(db, owner, data.model_dump(), s)
    except ReportError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="reports.schedule.update", module=MODULE,
               target_id=s.id, detail=s.name)
    return _schedules_out(db, [s])[0]


@router.post("/schedules/{schedule_id}/run")
def run_schedule(schedule_id: int, user: User = Depends(_write), db: Session = Depends(get_db)):
    s = _own_schedule(db, user, schedule_id)
    r = service.queue_schedule(db, s)
    db.refresh(s)
    if r is None:
        raise HTTPException(status_code=400, detail=s.last_error or "The schedule could not run")
    log_action(db, user_id=user.id, username=user.username, action="reports.schedule.run", module=MODULE,
               target_id=s.id, detail=f"{s.name} -> {r.code}")
    return {"schedule": _schedules_out(db, [s])[0], "report": _reports_out(db, [r])[0]}


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, user: User = Depends(_write), db: Session = Depends(get_db)):
    s = _own_schedule(db, user, schedule_id)
    name = s.name
    db.delete(s)
    db.commit()
    log_action(db, user_id=user.id, username=user.username, action="reports.schedule.delete", module=MODULE,
               target_id=schedule_id, detail=name)
    return {"deleted": schedule_id}


# ── settings ─────────────────────────────────────────────────────────────

class SettingsRequest(BaseModel):
    org_name: str = Field("", max_length=120)
    org_unit: str = Field("", max_length=120)
    logo: Optional[str] = Field(None, max_length=300_000)
    default_classification: Literal["public", "internal", "confidential"] = "internal"
    footer_text: str = Field("", max_length=300)
    retention_days: int = 365


@router.get("/settings/current")
def get_settings(_user: User = Depends(_read), db: Session = Depends(get_db)):
    return service.get_settings(db)


@router.put("/settings/current")
def put_settings(data: SettingsRequest, user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
                 db: Session = Depends(get_db)):
    try:
        out = service.save_settings(db, data.model_dump(), user)
    except ReportError as e:
        _fail(e)
    log_action(db, user_id=user.id, username=user.username, action="reports.settings", module=MODULE,
               detail="report settings changed")
    return out
