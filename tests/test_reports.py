"""
Reports: calendars and periods, the Persian text, validation and
permissions, building PDF and Excel from real module data, the archive
(hash, verify, retention, visibility), schedules (next run, queueing,
email delivery) and the failed-schedule alert.

Everything runs inside a rolled-back transaction.
"""
import importlib
import io
import json
from datetime import date, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, User, UserRole
from app.models.asset_types import AssetType
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.remediation import RemediationItem, RiskAcceptance
from app.models.report import Report, ReportFile, ReportSchedule
from app.models.risk import AssetRiskHistory
from app.models.user_permission import ModuleEnum, UserPermission
from app.modules.alerts import events as alert_events
from app.modules.reports import calendar as cal
from app.modules.reports import data, periods, service
from app.modules.reports.i18n import LOCALE_DIR, Tr
from app.modules.reports.service import ReportError
from app.modules.reports.strings import collect

api = importlib.import_module("app.modules.reports.router")


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


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


def _user(db, role=UserRole.ADMIN, modules=(), email=None):
    n = _n()
    u = User(username=f"rep_user_{n}", email=email or f"rep{n}@example.com", hashed_password="x", role=role,
             is_active=True)
    db.add(u)
    db.flush()
    for m in modules:
        db.add(UserPermission(user_id=u.id, module=m, can_read=True, can_write=True, can_delete=False))
    db.flush()
    return u


def _asset(db, category="network"):
    t = AssetType(type_name=f"Rep type {_n()}", category=category)
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"rep-asset-{_n()}", asset_type_id=t.id, ip_address=f"10.88.{_n() % 250}.{_n() % 250}")
    db.add(a)
    db.flush()
    return a


def _audit(db, asset, pct, when, fails=(("1.1.1", "high"),)):
    user = _user(db)
    s = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address, device_type="linux",
                     status="completed", started_at=when, completed_at=when, compliance_pct=pct)
    db.add(s)
    db.flush()
    for check, sev in fails:
        db.add(AuditResult(session_id=s.id, check_number=check, check_title=f"Check {check}", severity=sev,
                           status=CheckStatus.FAIL))
    db.flush()
    return s


def _item(db, asset, ref, first, due, sev="high", kev=False, resolved=None, source="audit"):
    i = RemediationItem(key=f"{source}:{asset.id}:{ref}:{_n()}", source=source, ref=ref, asset_id=asset.id,
                        asset_name=asset.asset_name, title=f"Finding {ref}", severity=sev, kev=kev,
                        status="resolved" if resolved else "open", due_at=due, first_seen_at=first,
                        last_seen_at=first, resolved_at=resolved, closed_reason="fixed" if resolved else None,
                        updated_at=first)
    db.add(i)
    db.flush()
    return i


def _params(**kw):
    p = {"period": {"preset": "custom", "from": "2026-09-01", "to": "2026-09-30"}, "compare": True,
         "scope": {"mode": "all"}}
    p.update(kw)
    return p


# ── calendar, periods, text ──────────────────────────────────────────────

def test_solar_hijri_conversion_and_calendar_steps():
    assert cal.to_jalali(date(2026, 10, 2)) == (1405, 7, 10)
    assert cal.from_jalali(1405, 1, 1) == date(2026, 3, 21)
    d = date(2000, 1, 1)
    for _ in range(4000):
        d += timedelta(days=3)
        assert cal.from_jalali(*cal.to_jalali(d)) == d
    assert cal.month_start(date(2026, 10, 2), "fa", -1) == date(2026, 8, 23)       # 1 Shahrivar 1405
    assert cal.month_start(date(2026, 10, 2), "en", -1) == date(2026, 9, 1)
    assert cal.quarter_start(date(2026, 10, 2), "fa") == date(2026, 9, 23)         # 1 Mehr = autumn
    assert cal.fmt_date(date(2026, 10, 2), "fa") == "۱۰ مهر ۱۴۰۵"
    assert cal.fmt_date(date(2026, 10, 2), "en") == "Oct 2, 2026"


def test_previous_month_follows_the_report_language():
    now = datetime(2026, 10, 2, 9, 0)
    fa, fa_prev = periods.resolve("previous_month", "fa", Tr("fa"), None, now)
    en, en_prev = periods.resolve("previous_month", "en", Tr("en"), None, now)
    assert (fa.first_day, fa.last_day) == (date(2026, 8, 23), date(2026, 9, 22))
    assert fa.label == "شهریور ۱۴۰۵" and fa_prev.label == "مرداد ۱۴۰۵"
    assert (en.first_day, en.last_day, en.label) == (date(2026, 9, 1), date(2026, 9, 30), "September 2026")
    assert en_prev.first_day == date(2026, 8, 1)
    rolling, before = periods.resolve("last_7_days", "en", Tr("en"), None, now)
    assert rolling.end == now and before.end == rolling.start
    with pytest.raises(periods.PeriodError):
        periods.resolve("custom", "en", Tr("en"), None, now, date(2026, 9, 10), date(2026, 9, 1))


def test_persian_numbers_and_every_report_string_is_translated():
    tr = Tr("fa")
    assert tr.num(1234.5, 1) == "۱٬۲۳۴٫۵" and tr.pct(83) == "۸۳٪" and tr.signed(-3) == "۳−"
    assert tr("{count} new", count=4) == "۴ جدید"
    assert "⁦" in tr("Lowest: {asset} at {pct}.", asset="FGT-Edge-01", pct="۵۸٪")
    assert Tr("en")("{count} new", count=4) == "4 new"
    fa = json.loads((LOCALE_DIR / "fa.json").read_text(encoding="utf-8"))
    assert collect() - set(fa) == set()


# ── shared figures ───────────────────────────────────────────────────────

def test_figures_as_of_a_time(db):
    a, b = _asset(db), _asset(db)
    db.add_all([AssetRiskHistory(asset_id=a.id, risk_score=70, risk_level="high", calculated_at=datetime(2026, 8, 5)),
                AssetRiskHistory(asset_id=a.id, risk_score=50, risk_level="medium", calculated_at=datetime(2026, 9, 5)),
                AssetRiskHistory(asset_id=b.id, risk_score=30, risk_level="low", calculated_at=datetime(2026, 9, 6))])
    db.flush()
    assert data.risk_at(db, [a.id, b.id], datetime(2026, 9, 1)) == {a.id: 70.0}
    assert data.risk_at(db, [a.id, b.id], datetime(2026, 10, 1)) == {a.id: 50.0, b.id: 30.0}

    _audit(db, a, 40.0, datetime(2026, 8, 10))
    _audit(db, a, 60.0, datetime(2026, 9, 10))
    assert data.compliance_at(db, [a.id], datetime(2026, 9, 1))[a.id].compliance_pct == 40.0
    assert data.compliance_at(db, [a.id], datetime(2026, 10, 1))[a.id].compliance_pct == 60.0

    start, end = datetime(2026, 9, 1), datetime(2026, 10, 1)
    _item(db, a, "late", datetime(2026, 8, 1), datetime(2026, 9, 1))                         # open, overdue
    _item(db, a, "soon", datetime(2026, 9, 20), datetime(2026, 10, 20))                      # open, new
    _item(db, a, "ok", datetime(2026, 8, 20), datetime(2026, 9, 19), resolved=datetime(2026, 9, 10))  # on time
    _item(db, a, "slow", datetime(2026, 8, 1), datetime(2026, 8, 31), resolved=datetime(2026, 9, 15))  # late
    _item(db, a, "after", datetime(2026, 8, 1), datetime(2026, 8, 31), resolved=datetime(2026, 10, 5))  # open then
    rem = data.remediation(db, {a.id}, start, end)
    assert {i.ref for i in rem.open} == {"late", "soon", "after"}
    assert {i.ref for i in rem.overdue} == {"late", "after"}
    assert {i.ref for i in rem.fixed} == {"ok", "slow"} and rem.fixed_on_time == 1 and rem.on_time_pct == 50.0
    assert {i.ref for i in rem.new} == {"soon"}


# ── validation and permissions ───────────────────────────────────────────

def test_request_validation(db):
    admin = _user(db)
    with pytest.raises(ReportError, match="Unknown report"):
        service.create(db, admin, "nope", "", "fa", ["pdf"], "internal", _params())
    with pytest.raises(ReportError, match="not available yet"):
        service.create(db, admin, "noc", "", "fa", ["pdf"], "internal", _params())
    with pytest.raises(ReportError, match="Choose PDF"):
        service.create(db, admin, "risk", "", "fa", [], "internal", _params())
    with pytest.raises(ReportError, match="at least one section"):
        service.create(db, admin, "risk", "", "fa", ["pdf"], "internal", _params(sections=["bogus"]))
    with pytest.raises(ReportError, match="asset filter"):
        service.create(db, admin, "risk", "", "fa", ["pdf"], "internal", _params(scope={"mode": "types"}))
    r = service.create(db, admin, "executive", "", "en", ["pdf"], "internal",
                       _params(sections=["summary", "appendix"]))
    assert r.formats == ["pdf", "xlsx"]                     # the appendix is an Excel file
    assert r.title == "Security executive summary" and r.code.startswith("RPT-2026-")
    assert service.create(db, admin, "risk", "", "fa", ["pdf"], "internal", _params()).code.startswith("RPT-1405-")


def test_permissions_decide_templates_and_sections(db):
    auditor = _user(db, UserRole.USER, modules=[ModuleEnum.REPORTS, ModuleEnum.AUDITING])
    with pytest.raises(ReportError) as e:
        service.create(db, auditor, "cve", "", "en", ["pdf"], "internal", _params())
    assert e.value.status_code == 403
    r = service.create(db, auditor, "executive", "", "en", ["pdf"], "internal",
                       _params(sections=["summary", "compliance", "vulnerabilities"]))
    out = service.build(db, r, now=datetime(2026, 10, 2))
    assert r.omitted == ["Vulnerabilities: no access to Vulnerabilities (CVE)"]
    assert out["files"]["pdf"][1][:4] == b"%PDF"
    cat = api.catalog(user=auditor, db=db)
    ids = {t["id"]: t for t in cat["templates"]}
    assert "cis_compliance" in ids and "cve" not in ids and ids["noc"]["available"] is False
    sections = {s["key"]: s["allowed"] for s in ids["executive"]["sections"]}
    assert sections["compliance"] is True and sections["vulnerabilities"] is False


# ── building and the archive ─────────────────────────────────────────────

def _scenario(db):
    a, b = _asset(db), _asset(db)
    _audit(db, a, 50.0, datetime(2026, 8, 15))
    _audit(db, a, 70.0, datetime(2026, 9, 15), fails=(("5.2.7", "critical"), ("1.1.1", "high")))
    _audit(db, b, 90.0, datetime(2026, 9, 20))
    for d, s in ((datetime(2026, 8, 20), 72), (datetime(2026, 9, 10), 64), (datetime(2026, 9, 25), 61)):
        db.add(AssetRiskHistory(asset_id=a.id, risk_score=s, risk_level="high", calculated_at=d))
    _item(db, a, "CVE-2024-0001", datetime(2026, 8, 1), datetime(2026, 9, 2), sev="critical", kev=True, source="cve")
    _item(db, b, "1.2.3", datetime(2026, 8, 25), datetime(2026, 9, 24), resolved=datetime(2026, 9, 12))
    db.flush()
    return a, b


def test_every_template_builds_pdf_and_excel_in_both_languages(db):
    from openpyxl import load_workbook
    from app.modules.reports.templates import TEMPLATES
    admin = _user(db)
    a, _ = _scenario(db)
    for lang in ("fa", "en"):
        for tid, tpl in TEMPLATES.items():
            r = service.create(db, admin, tid, "", lang, ["pdf", "xlsx"], "confidential",
                               _params(sections=[s.key for s in tpl.sections],
                                       scope={"mode": "assets", "values": [a.id]}))
            out = service.build(db, r, now=datetime(2026, 10, 2, 8))
            r.status = "ready"
            pdf_name, pdf = out["files"]["pdf"]
            assert pdf.startswith(b"%PDF") and out["pages"] >= 1, (lang, tid)
            assert pdf_name == f"{r.code}_{tid}.pdf"
            wb = load_workbook(io.BytesIO(out["files"]["xlsx"][1]))
            assert wb.worksheets[0].sheet_view.rightToLeft is (lang == "fa")


def test_run_stores_files_with_hash_and_verify_finds_them(db):
    admin = _user(db)
    _scenario(db)
    r = service.create(db, admin, "remediation", "Monthly remediation", "en", ["pdf", "xlsx"], "internal",
                       _params())
    claimed = service.claim_next(db)
    assert claimed.id == r.id and claimed.status == "running"
    service.run(db, claimed)
    db.refresh(r)
    assert r.status == "ready" and r.page_count >= 1 and r.period_start is not None
    files = {f.kind: f for f in db.query(ReportFile).filter(ReportFile.report_id == r.id)}
    assert set(files) == {"pdf", "xlsx"}
    hit = service.verify(db, files["pdf"].content)
    assert hit and hit[1].id == r.id
    assert service.verify(db, files["pdf"].content + b" ") is None
    resp = api.download(r.id, "pdf", user=admin, db=db)
    assert resp.body == files["pdf"].content and resp.headers["x-content-sha256"] == files["pdf"].sha256


def test_failed_build_is_recorded(db):
    gone = _user(db)
    r = service.create(db, gone, "risk", "", "en", ["pdf"], "internal", _params())
    gone.is_active = False
    db.flush()
    service.run(db, service.claim_next(db))
    db.refresh(r)
    assert r.status == "failed" and "active account" in r.error


def test_archive_visibility_cancel_pin_and_retention(db):
    admin = _user(db)
    alice = _user(db, UserRole.USER, modules=[ModuleEnum.REPORTS, ModuleEnum.RISK])
    bob = _user(db, UserRole.USER, modules=[ModuleEnum.REPORTS, ModuleEnum.RISK])
    mine = service.create(db, alice, "risk", "", "en", ["pdf"], "internal", _params())
    theirs = service.create(db, bob, "risk", "", "en", ["pdf"], "internal", _params())
    seen = {r.id for r in service.visible_reports(db, alice)}
    assert mine.id in seen and theirs.id not in seen
    assert {mine.id, theirs.id} <= {r.id for r in service.visible_reports(db, admin)}
    with pytest.raises(ReportError):
        service.get_visible(db, alice, theirs.id)
    listing = api.list_reports(view="mine", q=None, offset=0, limit=50, user=alice, db=db)
    assert [i["id"] for i in listing["items"]] == [mine.id] and listing["counts"]["running"] == 1

    service.cancel(db, mine)
    assert mine.status == "cancelled"
    with pytest.raises(ReportError):
        service.cancel(db, mine)
    for _ in range(3):
        service.create(db, alice, "risk", "", "en", ["pdf"], "internal", _params())
    with pytest.raises(ReportError) as e:
        service.create(db, alice, "risk", "", "en", ["pdf"], "internal", _params())
    assert e.value.status_code == 429

    old = datetime.utcnow() - timedelta(days=400)
    mine.created_at = old
    theirs.status, theirs.created_at, theirs.pinned = "ready", old, True
    db.flush()
    assert service.purge_old(db) == 1
    assert db.get(Report, theirs.id) is not None and db.get(Report, mine.id) is None


def test_preview_returns_a_pdf_without_keeping_it(db):
    admin = _user(db)
    before = db.query(Report).count()
    resp = api.preview(api.ReportRequest(template="risk", language="fa", formats=["pdf"], params=_params()),
                       user=admin, db=db)
    assert resp.body[:4] == b"%PDF" and db.query(Report).count() == before


def test_settings_validation(db):
    admin = _user(db)
    base = {"org_name": "Acme", "org_unit": "SOC", "logo": None, "default_classification": "confidential",
            "footer_text": "Internal use", "retention_days": 365}
    assert service.save_settings(db, base, admin)["org_name"] == "Acme"
    with pytest.raises(ReportError):
        service.save_settings(db, {**base, "retention_days": 5}, admin)
    with pytest.raises(ReportError, match="PNG or JPEG"):
        service.save_settings(db, {**base, "logo": "data:image/svg+xml;base64,PHN2Zz4="}, admin)


# ── schedules ────────────────────────────────────────────────────────────

def _schedule_payload(**kw):
    p = {"name": "Monthly for managers", "template": "risk", "language": "fa", "formats": ["pdf"],
         "classification": "internal", "params": {"period": {"preset": "previous_month"}, "scope": {"mode": "all"}},
         "frequency": "monthly", "monthday": 1, "run_time": "08:00", "recipient_users": [],
         "recipient_emails": ["ciso@example.com"], "attach": True, "enabled": True}
    p.update(kw)
    return p


def test_next_run_in_each_frequency_and_calendar():
    s = ReportSchedule(frequency="monthly", monthday=1, run_time="08:00", language="fa")
    assert service.next_run(s, datetime(2026, 10, 2, 9), None) == datetime(2026, 10, 23, 8)     # 1 Aban 1405
    s.language = "en"
    assert service.next_run(s, datetime(2026, 10, 2, 9), None) == datetime(2026, 11, 1, 8)
    s.frequency, s.weekday = "weekly", 5                                                        # Saturday
    assert service.next_run(s, datetime(2026, 10, 2, 9), None) == datetime(2026, 10, 3, 8)
    s.frequency = "daily"
    assert service.next_run(s, datetime(2026, 10, 2, 7), None) == datetime(2026, 10, 2, 8)
    assert service.next_run(s, datetime(2026, 10, 2, 8), None) == datetime(2026, 10, 3, 8)
    s.frequency, s.monthday, s.language = "quarterly", 1, "fa"
    assert service.next_run(s, datetime(2026, 10, 2, 9), None) == datetime(2026, 12, 22, 8)     # 1 Dey 1405


def test_schedule_validation(db):
    admin = _user(db)
    with pytest.raises(ReportError, match="moves with it"):
        service.save_schedule(db, admin, _schedule_payload(params=_params()))
    with pytest.raises(ReportError, match="recipient"):
        service.save_schedule(db, admin, _schedule_payload(recipient_emails=[]))
    with pytest.raises(ReportError, match="email address"):
        service.save_schedule(db, admin, _schedule_payload(recipient_emails=["not an email"]))
    with pytest.raises(ReportError, match="day of the month"):
        service.save_schedule(db, admin, _schedule_payload(monthday=31))
    s = service.save_schedule(db, admin, _schedule_payload())
    assert s.next_run_at is not None and s.title == "ریسک دارایی‌ها"


def test_due_schedule_queues_builds_and_emails(db, monkeypatch):
    sent = []
    monkeypatch.setattr("app.modules.alerts.channels.send_email",
                        lambda config, to, subject, body, html_body=None, attachments=None:
                        sent.append((to, subject, attachments)))
    monkeypatch.setattr("app.modules.alerts.channels.load_section", lambda db, section: {"host": "smtp"})
    admin = _user(db, email="boss@example.com")
    s = service.save_schedule(db, admin, _schedule_payload(recipient_users=[admin.id], classification="confidential",
                                                           recipient_emails=["outside@example.org"]))
    s.next_run_at = datetime.utcnow() - timedelta(minutes=1)
    db.flush()
    assert service.run_due_schedules(db) == 1
    assert s.next_run_at > datetime.utcnow() and s.last_report_id
    r = service.claim_next(db)
    assert r.schedule_id == s.id
    service.run(db, r)
    db.refresh(s)
    db.refresh(r)
    assert s.last_status == "sent" and r.delivered_to == ["boss@example.com"]
    assert "outside@example.org" in r.delivery_error                       # confidential stays inside
    to, subject, attachments = sent[0]
    assert to == ["boss@example.com"] and attachments[0][0].endswith(".pdf")
    assert attachments[0][2] == "application/pdf"


def test_failed_schedule_raises_an_alert(db):
    admin = _user(db)
    s = service.save_schedule(db, admin, _schedule_payload())
    s.last_status, s.last_error = "failed", "SMTP error: refused"
    db.flush()
    problems = alert_events._report_schedule_failed(db, {}, datetime.utcnow(), datetime.utcnow())
    mine = [p for p in problems if p.key == f"schedule:{s.id}"]
    assert mine and mine[0].owner_user_id == admin.id and "SMTP error" in mine[0].detail
    assert "reports.schedule_failed" in alert_events.EVENTS
