"""
Reports: validate a request, queue it, build it in the background, keep the
files with their SHA-256, run schedules and email their reports, and delete
old reports after the retention period.

A report is built with the permissions of the person who asked for it (or
the owner of its schedule) at build time: a section whose module that person
cannot read is left out, and the report says so.
"""
import hashlib
import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import User
from app.models.report import (CLASSIFICATIONS, FORMATS, FREQUENCIES, LANGUAGES, REPORT_CANCELLED, REPORT_FAILED,
                               REPORT_PENDING, REPORT_QUEUED, REPORT_READY, REPORT_RUNNING, Report, ReportFile,
                               ReportSchedule)
from app.models.system_config import SECTION_REPORTS, SECTION_SMTP, SystemConfigSetting
from app.models.user_permission import UserPermission
from app.modules.reports import calendar as cal
from app.modules.reports import periods, render, scope
from app.modules.reports.i18n import Tr
from app.modules.reports.templates import PLANNED, TEMPLATES, Ctx

logger = logging.getLogger(__name__)

MAX_PENDING_PER_USER = 3
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_LOGO_BYTES = 200 * 1024
STALE_RUNNING = timedelta(minutes=30)

DEFAULT_SETTINGS = {"org_name": "NGCorion", "org_unit": "", "logo": None, "default_classification": "internal",
                    "footer_text": "", "retention_days": 365}

MODULE_LABELS = {"risk": "Risk Analysis", "auditing": "Auditing", "cve": "Vulnerabilities (CVE)",
                 "remediation": "Remediation", "backup": "Backup & Restore", "hardening": "Hardening",
                 "asset_list": "Asset List", "noc": "NOC", "architecture_validation": "Architecture Validation",
                 "logs": "Logs", "system_config": "System Configuration"}

MIME = {"pdf": "application/pdf", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


class ReportError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ── settings ─────────────────────────────────────────────────────────────

def get_settings(db: Session) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION_REPORTS).first()
    stored = (row.config_json or {}) if row else {}
    return {k: stored.get(k, v) for k, v in DEFAULT_SETTINGS.items()}


def save_settings(db: Session, payload: Dict, user: User) -> Dict:
    clean = dict(DEFAULT_SETTINGS)
    clean["org_name"] = (payload.get("org_name") or "").strip()[:120] or DEFAULT_SETTINGS["org_name"]
    clean["org_unit"] = (payload.get("org_unit") or "").strip()[:120]
    clean["footer_text"] = (payload.get("footer_text") or "").strip()[:300]
    if payload.get("default_classification") not in CLASSIFICATIONS:
        raise ReportError("Unknown classification")
    clean["default_classification"] = payload["default_classification"]
    days = int(payload.get("retention_days") or 0)
    if not 30 <= days <= 3650:
        raise ReportError("Keep reports between 30 and 3650 days")
    clean["retention_days"] = days
    logo = payload.get("logo")
    if logo:
        if not (logo.startswith("data:image/png;base64,") or logo.startswith("data:image/jpeg;base64,")):
            raise ReportError("The logo must be a PNG or JPEG image")
        if len(logo) > MAX_LOGO_BYTES * 4 // 3 + 64:
            raise ReportError("The logo must be smaller than 200 KB")
        clean["logo"] = logo
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION_REPORTS).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION_REPORTS)
        db.add(row)
    row.config_json = clean
    row.updated_by = user.id
    db.commit()
    return get_settings(db)


# ── permissions ──────────────────────────────────────────────────────────

def _role(user: User) -> str:
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def can_read(db: Session, user: User, module: Optional[str]) -> bool:
    if module is None or _role(user) == "admin":
        return True
    perm = (db.query(UserPermission)
            .filter(UserPermission.user_id == user.id, UserPermission.module == module.upper()).first())
    return bool(perm and perm.can_read)


def template_visible(db: Session, user: User, tpl) -> bool:
    if getattr(tpl, "admin_only", False):
        return _role(user) == "admin"
    if tpl.module:
        return can_read(db, user, tpl.module)
    return any(can_read(db, user, s.module) for s in tpl.sections) if tpl.sections else True


def visible_reports(db: Session, user: User):
    q = db.query(Report)
    if _role(user) != "admin":
        own_schedules = [sid for (sid,) in db.query(ReportSchedule.id).filter(ReportSchedule.owner_id == user.id)]
        q = q.filter((Report.created_by == user.id) | (Report.schedule_id.in_(own_schedules or [-1])))
    return q


def get_visible(db: Session, user: User, report_id: int) -> Report:
    r = visible_reports(db, user).filter(Report.id == report_id).first()
    if r is None:
        raise ReportError("Report not found", 404)
    return r


# ── request validation ───────────────────────────────────────────────────

def validate(db: Session, user: User, template: str, language: str, formats: List[str], classification: str,
             params: Dict, for_schedule: bool = False) -> Tuple[str, List[str], Dict]:
    tpl = TEMPLATES.get(template)
    if tpl is None:
        raise ReportError("Unknown report" if template not in {p.id for p in PLANNED}
                          else "This report is not available yet")
    if not template_visible(db, user, tpl):
        raise ReportError("You have no access to this report", 403)
    if language not in LANGUAGES:
        raise ReportError("Unknown language")
    if classification not in CLASSIFICATIONS:
        raise ReportError("Unknown classification")
    formats = [f for f in FORMATS if f in (formats or [])]
    if not formats:
        raise ReportError("Choose PDF, Excel or both")
    params = dict(params or {})
    period = dict(params.get("period") or {})
    preset = period.get("preset") or tpl.default_period
    if preset not in periods.PRESETS:
        raise ReportError("Unknown period")
    if for_schedule and preset == "custom":
        raise ReportError("A schedule needs a period that moves with it, not fixed dates")
    if preset == "custom":
        try:
            date.fromisoformat(period.get("from") or "")
            date.fromisoformat(period.get("to") or "")
        except ValueError as exc:
            raise ReportError("Choose the start and end of the period") from exc
    try:
        params["scope"] = scope.normalize(params.get("scope"))
    except scope.ScopeError as exc:
        raise ReportError(str(exc)) from exc
    keys = [s.key for s in tpl.sections]
    sections = [k for k in (params.get("sections") or [s.key for s in tpl.sections if s.default]) if k in keys]
    if not sections:
        raise ReportError("Choose at least one section")
    if any(tpl.section(k).excel_only for k in sections) and "xlsx" not in formats:
        formats.append("xlsx")
    options = {}
    for o in tpl.options:
        v = (params.get("options") or {}).get(o.key, o.default)
        if o.kind == "bool":
            v = bool(v)
        elif o.kind == "choice":
            v = v if v in {c[0] for c in o.choices} else o.default
        elif o.kind == "multi":
            v = [x for x in (v or []) if x in {c[0] for c in o.choices}]
        elif o.kind == "int":
            try:
                v = int(v) if v not in (None, "") else None
            except (TypeError, ValueError):
                v = None
        options[o.key] = v
    if tpl.id == "audit_session":
        if options.get("audit_mode") == "session" and not options.get("audit_session"):
            raise ReportError("Choose the audit this report describes")
        if for_schedule and options.get("audit_mode") == "session":
            raise ReportError("A schedule describes the latest audit of each asset, not one fixed audit")
    clean = {"period": {"preset": preset, "from": period.get("from"), "to": period.get("to")},
             "compare": bool(params.get("compare", True)) and tpl.uses_period, "scope": params["scope"], "sections": sections,
             "options": options, "orientation": "landscape" if params.get("orientation") == "landscape" else "portrait"}
    return tpl.id, formats, clean


def create(db: Session, user: User, template: str, title: str, language: str, formats: List[str],
           classification: str, params: Dict, schedule: Optional[ReportSchedule] = None) -> Report:
    template, formats, params = validate(db, user, template, language, formats, classification, params)
    if schedule is None:
        pending = (db.query(Report).filter(Report.created_by == user.id, Report.status.in_(REPORT_PENDING),
                                           Report.schedule_id.is_(None)).count())
        if pending >= MAX_PENDING_PER_USER:
            raise ReportError("You already have 3 reports being built; wait for one to finish", 429)
    title = (title or "").strip()[:200] or Tr(language)(TEMPLATES[template].title)
    r = Report(template=template, title=title, language=language, formats=formats, classification=classification,
               params=params, status=REPORT_QUEUED, created_by=user.id, schedule_id=schedule.id if schedule else None,
               created_at=datetime.utcnow())
    db.add(r)
    db.flush()
    r.code = f"RPT-{cal.year_of(r.created_at.date(), language)}-{r.id:04d}"
    db.commit()
    return r


# ── building ─────────────────────────────────────────────────────────────

def _timezone(db: Session):
    from app.modules.alerts.channels import local_timezone
    return local_timezone(db)


def build(db: Session, report: Report, now: Optional[datetime] = None) -> Dict:
    """Run the template and render the files. Returns {kind: (filename, bytes)} plus page count."""
    now = now or datetime.utcnow()
    tpl = TEMPLATES[report.template]
    user = db.get(User, report.created_by) if report.created_by else None
    if user is None or not user.is_active:
        raise ReportError("The person this report is built for no longer has an active account")
    if tpl.admin_only and _role(user) != "admin":
        raise ReportError("Only an administrator can build this report", 403)
    tr = Tr(report.language)
    tz = _timezone(db)
    params = report.params or {}
    p = params.get("period") or {}
    try:
        period, prev = periods.resolve(p.get("preset"), report.language, tr, tz, now,
                                       date.fromisoformat(p["from"]) if p.get("from") else None,
                                       date.fromisoformat(p["to"]) if p.get("to") else None)
    except periods.PeriodError as exc:
        raise ReportError(str(exc)) from exc
    compare = bool(params.get("compare", True))
    assets = scope.assets(db, params.get("scope") or {})
    report.period_start, report.period_end = period.start, period.end

    perms = {}

    def can(module):
        if module not in perms:
            perms[module] = can_read(db, user, module)
        return perms[module]

    omitted, enabled = [], []
    for key in params.get("sections") or []:
        s = tpl.section(key)
        if s.module and not can(s.module):
            omitted.append(tr("{section}: no access to {module}", section=tr(s.title),
                              module=tr(MODULE_LABELS.get(s.module, s.module))))
        else:
            enabled.append(key)
    if not enabled:
        raise ReportError("None of the chosen sections can be built with your permissions")

    ctx = Ctx(db, tr, tz, now, period, prev if compare else None, assets, params.get("options") or {}, enabled, can,
              report.formats)
    ctx.user = user
    blocks = tpl.build(ctx)

    def cut_note(shown, total):
        if "xlsx" in report.formats:
            return tr("Showing {shown} of {total}; the Excel file has the full list.", shown=shown, total=total)
        return tr("Showing {shown} of {total}; build the report as Excel for the full list.", shown=shown, total=total)

    sections = [{"key": k, "title": tr(tpl.section(k).title), "blocks": blocks.get(k) or [],
                 "excel_only": tpl.section(k).excel_only, "cut_note": cut_note} for k in enabled]

    settings = get_settings(db)
    local_now = periods.local_now(now, tz)
    by = user.username
    if report.schedule_id:
        sched = db.get(ReportSchedule, report.schedule_id)
        if sched:
            by = tr("Schedule \"{name}\" of {user}", name=sched.name, user=user.username)
    if tpl.uses_period:
        period_line = tr("Period: {label}", label=period.label)
        if compare and prev:
            period_line += " · " + tr("compared with {label}", label=prev.label)
    else:
        period_line = ctx.header_line or tr("As of {date}", date=cal.fmt_datetime(periods.local_now(now, tz),
                                                                                    report.language))
    if ctx.scope_line is not None:
        scope_line = ctx.scope_line
    elif tpl.uses_assets:
        scope_line = scope.describe(db, params.get("scope") or {}, len(assets), tr)
    else:
        scope_line = ""
    classification = tr({"public": "Public", "internal": "Internal", "confidential": "Confidential"}
                        [report.classification])
    meta = {
        "lang": report.language, "rtl": tr.rtl, "title": report.title, "org_name": settings["org_name"],
        "org_unit": settings["org_unit"], "logo": settings["logo"], "period_line": period_line,
        "scope_line": scope_line, "classification": report.classification,
        "classification_label": tr("Classification: {level}", level=classification),
        "footer_start": f"{tr.isolate(report.code)} · {tr('Generated')} {cal.fmt_datetime(local_now, report.language)}",
        "page_word": tr("Page"), "of_word": tr("of"), "landscape": params.get("orientation") == "landscape",
        "omitted": omitted, "t_omitted": tr("Left out of this report"), "t_summary": tr("Summary"),
        "footer_text": settings["footer_text"],
        "about": [(tr("Report ID"), report.code), (tr("Generated"), cal.fmt_datetime(local_now, report.language)),
                  (tr("Requested by"), by), (tr("Report"), tr(tpl.title)),
                  (tr("Period"), period.label if tpl.uses_period else period_line),
                  *([(tr("Assets"), scope_line)] if scope_line else []),
                  (tr("Data"), tr("Figures come from NGCorion as they were when the report was built. The SHA-256 "
                                  "of this file is kept in the report archive, where its authenticity can be "
                                  "checked."))],
    }
    files, pages = {}, None
    stem = f"{report.code}_{report.template}"
    if "pdf" in report.formats:
        content, pages = render.pdf(meta, sections)
        files["pdf"] = (f"{stem}.pdf", content)
    if "xlsx" in report.formats:
        files["xlsx"] = (f"{stem}.xlsx", render.xlsx(meta, sections, tr.rtl))
    report.omitted = omitted or None
    return {"files": files, "pages": pages}


def run(db: Session, report: Report) -> None:
    """Build a claimed report and store the outcome."""
    try:
        out = build(db, report)
        for kind, (filename, content) in out["files"].items():
            db.add(ReportFile(report_id=report.id, kind=kind, filename=filename, size=len(content),
                              sha256=hashlib.sha256(content).hexdigest(), content=content))
        report.page_count = out["pages"]
        report.status, report.progress, report.error = REPORT_READY, 100, None
    except ReportError as exc:
        db.rollback()
        report = db.get(Report, report.id)
        report.status, report.error = REPORT_FAILED, exc.message
    except Exception as exc:  # noqa: BLE001 - recorded on the report
        logger.exception("[reports] building %s failed", report.id)
        db.rollback()
        report = db.get(Report, report.id)
        report.status, report.error = REPORT_FAILED, f"Building the report failed: {type(exc).__name__}"
    report.finished_at = datetime.utcnow()
    db.commit()
    if report.schedule_id:
        deliver(db, report)


def claim_next(db: Session) -> Optional[Report]:
    r = (db.query(Report).filter(Report.status == REPORT_QUEUED).order_by(Report.id)
         .with_for_update(skip_locked=True).first())
    if r is None:
        db.rollback()
        return None
    r.status, r.started_at, r.progress = REPORT_RUNNING, datetime.utcnow(), 10
    db.commit()
    return r


def fail_stale(db: Session, now: Optional[datetime] = None) -> int:
    """Reports left 'running' by a worker that stopped."""
    now = now or datetime.utcnow()
    rows = (db.query(Report).filter(Report.status == REPORT_RUNNING, Report.started_at < now - STALE_RUNNING).all())
    for r in rows:
        r.status, r.error, r.finished_at = REPORT_FAILED, "Building was interrupted; build the report again", now
    if rows:
        db.commit()
    return len(rows)


def cancel(db: Session, report: Report) -> None:
    if report.status != REPORT_QUEUED:
        raise ReportError("Only a report that has not started can be cancelled", 409)
    report.status, report.finished_at = REPORT_CANCELLED, datetime.utcnow()
    db.commit()


def purge_old(db: Session, now: Optional[datetime] = None) -> int:
    now = now or datetime.utcnow()
    days = int(get_settings(db)["retention_days"])
    rows = (db.query(Report).filter(Report.pinned.is_(False), Report.status.notin_(REPORT_PENDING),
                                    Report.created_at < now - timedelta(days=days)).all())
    for r in rows:
        db.delete(r)
    if rows:
        db.commit()
    return len(rows)


def verify(db: Session, content: bytes) -> Optional[Tuple[ReportFile, Report]]:
    digest = hashlib.sha256(content).hexdigest()
    f = db.query(ReportFile).filter(ReportFile.sha256 == digest).first()
    return (f, db.get(Report, f.report_id)) if f else None


# ── schedules ────────────────────────────────────────────────────────────

def _parse_time(value: str) -> time:
    try:
        h, m = (int(x) for x in (value or "").split(":"))
        return time(h, m)
    except (ValueError, TypeError) as exc:
        raise ReportError("Enter the time as HH:MM") from exc


def _utc(local: datetime, tz) -> datetime:
    if tz is None:
        return local
    return local.replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)


def next_run(s: ReportSchedule, after_utc: datetime, tz) -> datetime:
    """The first run strictly after `after_utc`, in the schedule's calendar and the system time zone."""
    at = _parse_time(s.run_time)
    today = periods.local_now(after_utc, tz).date()
    candidates = []
    if s.frequency == "daily":
        candidates = [today + timedelta(days=k) for k in range(0, 3)]
    elif s.frequency == "weekly":
        candidates = [today + timedelta(days=k) for k in range(0, 15) if (today + timedelta(days=k)).weekday() ==
                      (s.weekday if s.weekday is not None else 5)]
    elif s.frequency == "monthly":
        candidates = [cal.with_day(cal.month_start(today, s.language, k), s.monthday or 1, s.language)
                      for k in range(0, 3)]
    elif s.frequency == "quarterly":
        candidates = [cal.with_day(cal.quarter_start(today, s.language, k), s.monthday or 1, s.language)
                      for k in range(0, 3)]
    for d in candidates:
        when = _utc(datetime.combine(d, at), tz)
        if when > after_utc:
            return when
    raise ReportError("Could not work out the next run")


def save_schedule(db: Session, user: User, payload: Dict, schedule: Optional[ReportSchedule] = None) -> ReportSchedule:
    template, formats, params = validate(db, user, payload.get("template"), payload.get("language"),
                                         payload.get("formats"), payload.get("classification"),
                                         payload.get("params"), for_schedule=True)
    name = (payload.get("name") or "").strip()[:200]
    if not name:
        raise ReportError("Give the schedule a name")
    frequency = payload.get("frequency")
    if frequency not in FREQUENCIES:
        raise ReportError("Unknown frequency")
    _parse_time(payload.get("run_time"))
    weekday = payload.get("weekday")
    monthday = payload.get("monthday")
    if frequency == "weekly" and weekday not in range(7):
        raise ReportError("Choose the day of the week")
    if frequency in ("monthly", "quarterly") and monthday not in range(1, 29):
        raise ReportError("Choose a day of the month between 1 and 28")
    users = sorted({int(u) for u in payload.get("recipient_users") or []})
    if users and db.query(User).filter(User.id.in_(users)).count() != len(users):
        raise ReportError("Unknown recipient")
    emails = []
    for e in payload.get("recipient_emails") or []:
        e = (e or "").strip()
        if e:
            if "@" not in e or " " in e or len(e) > 254:
                raise ReportError(f"Not an email address: {e}")
            emails.append(e.lower())
    if not users and not emails:
        raise ReportError("Add at least one recipient")
    s = schedule or ReportSchedule(owner_id=user.id, created_at=datetime.utcnow())
    s.name, s.template, s.language, s.formats, s.classification, s.params = (
        name, template, payload["language"], formats, payload["classification"], params)
    s.title = (payload.get("title") or "").strip()[:200] or Tr(payload["language"])(TEMPLATES[template].title)
    s.frequency, s.run_time = frequency, payload["run_time"]
    s.weekday = weekday if frequency == "weekly" else None
    s.monthday = monthday if frequency in ("monthly", "quarterly") else None
    s.recipient_users, s.recipient_emails = users, sorted(set(emails))
    s.attach = bool(payload.get("attach", True))
    s.enabled = bool(payload.get("enabled", True))
    s.updated_at = datetime.utcnow()
    if schedule is None:
        db.add(s)
    s.next_run_at = next_run(s, datetime.utcnow(), _timezone(db)) if s.enabled else None
    db.commit()
    return s


def queue_schedule(db: Session, s: ReportSchedule, now: Optional[datetime] = None) -> Optional[Report]:
    """Queue one run of a schedule (due, or "run now")."""
    now = now or datetime.utcnow()
    owner = db.get(User, s.owner_id)
    s.last_run_at = now
    try:
        if owner is None or not owner.is_active:
            raise ReportError("The owner of this schedule no longer has an active account")
        r = create(db, owner, s.template, s.title, s.language, s.formats, s.classification, s.params, schedule=s)
        s.last_report_id, s.last_status, s.last_error = r.id, "running", None
        db.commit()
        return r
    except ReportError as exc:
        db.rollback()
        s = db.get(ReportSchedule, s.id)
        s.last_run_at, s.last_status, s.last_error = now, "failed", exc.message
        db.commit()
        return None


def run_due_schedules(db: Session, now: Optional[datetime] = None) -> int:
    now = now or datetime.utcnow()
    due = (db.query(ReportSchedule).filter(ReportSchedule.enabled.is_(True), ReportSchedule.next_run_at.isnot(None),
                                           ReportSchedule.next_run_at <= now)
           .with_for_update(skip_locked=True).all())
    tz = _timezone(db)
    for s in due:
        s.next_run_at = next_run(s, now, tz)
        db.commit()
        queue_schedule(db, s, now)
    return len(due)


def recipients(db: Session, s: ReportSchedule, classification: str) -> Tuple[List[str], List[str]]:
    """(addresses to send to, external addresses left out because the report is confidential)"""
    users = db.query(User).filter(User.id.in_(s.recipient_users or [-1]), User.is_active.is_(True)).all()
    to = [u.email for u in users if u.email]
    skipped = []
    for e in s.recipient_emails or []:
        if classification == "confidential":
            skipped.append(e)
        elif e not in to:
            to.append(e)
    return to, skipped


def deliver(db: Session, report: Report) -> None:
    """Email a scheduled report and record the outcome on the report and its schedule."""
    from app.modules.alerts.channels import DeliveryError, load_section, send_email
    s = db.get(ReportSchedule, report.schedule_id)
    if s is None:
        return
    if report.status != REPORT_READY:
        s.last_status, s.last_error = "failed", report.error or "The report could not be built"
        db.commit()
        return
    tr = Tr(report.language)
    to, skipped = recipients(db, s, report.classification)
    if not to:
        report.delivery_error = tr("No recipient with an email address.")
        s.last_status, s.last_error = "failed", report.delivery_error
        db.commit()
        return
    files = db.query(ReportFile).filter(ReportFile.report_id == report.id).all()
    total = sum(f.size for f in files)
    attach = s.attach and total <= MAX_ATTACHMENT_BYTES
    period = ""
    if report.period_start and report.period_end:
        tz = _timezone(db)
        first = periods.local_now(report.period_start, tz).date()
        last = periods.local_now(report.period_end - timedelta(seconds=1), tz).date()
        period = tr("{start} to {end}", start=cal.fmt_date(first, report.language),
                    end=cal.fmt_date(last, report.language))
    subject = f"{report.title} · {period}" if period else report.title
    lines = [tr("Report {code}: {title}", code=report.code, title=report.title)]
    if period:
        lines.append(tr("Period: {label}", label=period))
    lines.append(tr("The report is attached.") if attach else
                 tr("The report is in NGCorion under Reports > Archive."))
    if s.attach and not attach:
        lines.append(tr("It was not attached because it is larger than 10 MB."))
    try:
        send_email(load_section(db, SECTION_SMTP), to, subject, "\n".join(lines),
                   attachments=[(f.filename, f.content, MIME[f.kind]) for f in files] if attach else None)
        report.delivered_to, report.delivery_error = to, None
        s.last_status, s.last_error = "sent", None
        if skipped:
            report.delivery_error = tr("Not sent outside the organization because the report is confidential: "
                                       "{emails}", emails=", ".join(skipped))
    except DeliveryError as exc:
        report.delivery_error = str(exc)
        s.last_status, s.last_error = "failed", str(exc)
    db.commit()
