"""
Report templates.

A template is a list of sections. Each section needs read access to one
module and builds "blocks" - KPIs, bullet points, a chart, bars, a table, a
note. The PDF layout and the Excel writer both work from those blocks, so
the two formats always say the same thing (render.py).

Phase 1: executive summary, CIS compliance, CVE, asset risk, remediation.
The templates in PLANNED are shown in the catalog but cannot be built yet.
"""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Sequence

from sqlalchemy.orm import Session

from app.models.audit import AuditResult, CheckStatus
from app.models.backup import DeviceBackup
from app.models.hardening import HardeningAction
from app.models.remediation import ACCEPT_APPROVED, RiskAcceptance
from app.models.risk import AssetRiskScore
from app.modules.reports import calendar as cal
from app.modules.reports import charts, data
from app.modules.reports.i18n import Tr
from app.modules.reports.periods import Period

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── definitions ──────────────────────────────────────────────────────────

@dataclass
class Section:
    key: str
    title: str
    module: Optional[str]            # read permission needed (ModuleEnum value), None = none
    hint: str = ""
    default: bool = True
    excel_only: bool = False


@dataclass
class Option:
    key: str
    label: str
    kind: str                        # bool | choice | multi | int (set by the page that links here)
    default: object = None
    choices: Sequence = ()           # [(value, label)]


@dataclass
class Template:
    id: str
    title: str
    description: str
    group: str
    module: Optional[str]            # needed to see the template at all
    sections: List[Section] = field(default_factory=list)
    options: List[Option] = field(default_factory=list)
    default_period: str = "previous_month"
    available: bool = True
    build: Optional[Callable] = None  # (ctx) -> {section key: [blocks]}
    uses_period: bool = True          # False: the report describes one moment or one audit, not a period
    admin_only: bool = False
    uses_assets: bool = True          # False: the asset filter does not apply (user activity)

    def section(self, key: str) -> Section:
        return next(s for s in self.sections if s.key == key)


GROUPS = (
    ("management", "Management"),
    ("audit", "Audit and hardening"),
    ("vulnerability", "Vulnerability, risk and remediation"),
    ("infrastructure", "Assets and infrastructure"),
    ("system", "System"),
)


# ── build context ────────────────────────────────────────────────────────

class Ctx:
    """Everything a template needs while it builds."""

    def __init__(self, db: Session, tr: Tr, tz, now: datetime, period: Period, prev: Optional[Period],
                 assets: list, options: Dict, sections: List[str], can: Callable[[str], bool],
                 formats: Sequence[str]):
        self.db, self.tr, self.lang, self.tz, self.now = db, tr, tr.lang, tz, now
        self.period, self.prev = period, prev
        self.assets = assets
        self.ids = {a.id for a in assets}
        self.by_id = {a.id: a for a in assets}
        self.options = options or {}
        self.sections = sections
        self.can = can
        self.formats = formats
        self.user = None                  # who the report is built for (set by the service)
        self.header_line: Optional[str] = None   # replaces the period line, for reports without a period
        self.scope_line: Optional[str] = None    # replaces the asset line; "" leaves it out
        self._cache: Dict = {}

    def on(self, key: str) -> bool:
        return key in self.sections

    def local(self, dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        from app.modules.reports.periods import local_now
        return local_now(dt, self.tz)

    def date(self, dt: Optional[datetime]) -> str:
        return cal.fmt_date(self.local(dt), self.lang) if dt else "—"

    def short(self, dt: Optional[datetime]) -> str:
        return cal.fmt_short(self.local(dt), self.lang) if dt else "—"

    def cached(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    # shared figures, computed once per report
    def remediation(self, at_end_of_prev: bool = False, sources=None) -> data.Remediation:
        p = self.prev if at_end_of_prev else self.period
        key = ("rem", at_end_of_prev, tuple(sources or ()))
        return self.cached(key, lambda: data.remediation(self.db, self.ids, p.start, p.end, sources))

    def risk(self, prev: bool = False) -> Dict[int, float]:
        p = self.prev if prev else self.period
        return self.cached(("risk", prev), lambda: data.risk_at(self.db, self.ids, p.end))

    def compliance(self, prev: bool = False) -> Dict:
        p = self.prev if prev else self.period
        return self.cached(("cis", prev), lambda: data.compliance_at(self.db, self.ids, p.end))

    def cve(self) -> List[dict]:
        def load():
            from app.modules.cve import findings
            return [f for f in findings.compute(self.db)["findings"] if f["asset_id"] in self.ids]
        return self.cached("cve", load)


# ── blocks ───────────────────────────────────────────────────────────────

def kpi(label: str, value: str, delta: Optional[str] = None, good: Optional[bool] = None, sub: str = "") -> dict:
    return {"label": label, "value": value, "delta": delta, "good": good, "sub": sub}


def kpis(items: List[dict]) -> dict:
    return {"type": "kpis", "items": [i for i in items if i]}


def bullets(items: List[str]) -> dict:
    return {"type": "bullets", "items": [i for i in items if i]}


def note(text: str) -> dict:
    return {"type": "note", "text": text}


def col(label: str, mono: bool = False, num: bool = False, width: Optional[str] = None) -> dict:
    return {"label": label, "mono": mono, "num": num, "width": width}


def cell(text, value=None, cls: str = "") -> dict:
    return {"text": text, "value": text if value is None else value, "cls": cls}


def table(sheet: str, columns: List[dict], rows: List[list], empty: str, pdf_limit: Optional[int] = None,
          title: Optional[str] = None) -> dict:
    return {"type": "table", "sheet": sheet, "columns": columns, "rows": rows, "empty": empty,
            "pdf_limit": pdf_limit, "title": title}


def bars(rows: List[dict], legend: Optional[List] = None, mono_labels: bool = True) -> dict:
    """rows: [{"label", "text", "segments": [(percent of track, color)]}]"""
    return {"type": "bars", "rows": rows, "legend": legend or [], "mono_labels": mono_labels}


def chart(drawn, caption: str = "") -> Optional[dict]:
    svg, labels = drawn
    return {"type": "chart", "svg": svg, "xlabels": labels, "caption": caption} if svg else None


def two(left: List[dict], right: List[dict]) -> dict:
    return {"type": "columns", "left": [b for b in left if b], "right": [b for b in right if b]}


# ── shared helpers ───────────────────────────────────────────────────────

def _delta(ctx: Ctx, cur, prev, lower_is_better: bool, unit: str = "", decimals: int = 0, pct: bool = False):
    """(delta text, good?) against the previous period, or (None, None)."""
    if ctx.prev is None or cur is None or prev is None:
        return None, None
    diff = round(cur - prev, decimals)
    if diff == 0:
        return ctx.tr("no change"), None
    good = (diff < 0) if lower_is_better else (diff > 0)
    text = ctx.tr.signed(diff, decimals, ("٪" if ctx.lang == "fa" else "%") if pct else unit)
    return text, good


def _sev_cell(ctx: Ctx, severity: str, kev: bool = False) -> dict:
    text = ctx.tr.severity(severity)
    if kev:
        text += " · KEV"
    return cell(text, cls=f"sev sev-{(severity or '').lower()}")


def _pct(ctx: Ctx, v: Optional[float]) -> dict:
    return cell(ctx.tr.pct(v) if v is not None else "—", value=None if v is None else round(v, 1), cls="num")


def _num(ctx: Ctx, v, decimals: int = 0) -> dict:
    return cell(ctx.tr.num(v, decimals) if v is not None else "—", value=v, cls="num")


def _owner_names(db: Session, ids) -> Dict[int, str]:
    from app.models import User
    ids = {i for i in ids if i}
    return dict(db.query(User.id, User.username).filter(User.id.in_(ids)).all()) if ids else {}


def _days_late(ctx: Ctx, due: Optional[datetime]) -> str:
    if due is None:
        return "—"
    days = max(0, (ctx.period.end - due).days)
    return ctx.tr("{days} days", days=days) if days != 1 else ctx.tr("1 day")


DEVICE_NAMES = {"cisco": "Cisco", "fortinet": "Fortinet", "linux": "Linux", "windows": "Windows",
                "apache": "Apache", "mongodb": "MongoDB", "mssql": "SQL Server",
                "active_directory": "Active Directory", "dns_server": "Windows DNS Server",
                "dhcp_server": "Windows DHCP Server", "iis": "IIS"}


def _device(value) -> str:
    raw = str(value.value if hasattr(value, "value") else value or "")
    return DEVICE_NAMES.get(raw.lower(), raw)


def _compliance_value(s) -> Optional[float]:
    return float(s.compliance_pct) if s is not None and s.compliance_pct is not None else None


# ── executive summary ────────────────────────────────────────────────────

def _executive(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out = ctx.tr, {}
    can_risk, can_cis, can_rem, can_cve = (ctx.can("risk"), ctx.can("auditing"), ctx.can("remediation"),
                                          ctx.can("cve"))

    risk_now = data.average(ctx.risk().values()) if can_risk else None
    risk_prev = data.average(ctx.risk(prev=True).values()) if can_risk and ctx.prev else None
    cis_now = data.average(_compliance_value(s) for s in ctx.compliance().values()) if can_cis else None
    cis_prev = (data.average(_compliance_value(s) for s in ctx.compliance(prev=True).values())
                if can_cis and ctx.prev else None)
    rem = ctx.remediation() if can_rem else None
    rem_prev = ctx.remediation(at_end_of_prev=True) if can_rem and ctx.prev else None

    if ctx.on("summary"):
        items = []
        if can_risk:
            d, g = _delta(ctx, risk_now, risk_prev, True)
            items.append(kpi(tr("Average risk score"), tr.num(risk_now) if risk_now is not None else "—", d, g))
        if can_cis:
            d, g = _delta(ctx, cis_now, cis_prev, False, pct=True)
            items.append(kpi(tr("CIS compliance"), tr.pct(cis_now) if cis_now is not None else "—", d, g))
        if rem is not None:
            crit = sum(1 for i in rem.open if i.severity == "critical")
            d, g = _delta(ctx, len(rem.open), len(rem_prev.open) if rem_prev else None, True)
            items.append(kpi(tr("Open findings"), tr.num(len(rem.open)), d, g,
                             sub=tr("{count} critical", count=crit)))
            d, g = _delta(ctx, len(rem.overdue), len(rem_prev.overdue) if rem_prev else None, True)
            items.append(kpi(tr("Past the deadline"), tr.num(len(rem.overdue)), d, g))
            d, g = _delta(ctx, rem.on_time_pct, rem_prev.on_time_pct if rem_prev else None, False, pct=True)
            items.append(kpi(tr("Fixed on time"), tr.pct(rem.on_time_pct) if rem.on_time_pct is not None else "—",
                             d, g, sub=tr("{count} fixed in the period", count=len(rem.fixed))))
            d, g = _delta(ctx, rem.mttr_days, rem_prev.mttr_days if rem_prev else None, True, decimals=1,
                          unit=" " + tr("days"))
            items.append(kpi(tr("Average time to fix"),
                             tr("{days} days", days=round(rem.mttr_days, 1)) if rem.mttr_days is not None else "—",
                             d, g))
        blocks = [kpis(items)] if items else []

        points = []
        if rem is not None and rem.overdue:
            kev = [i for i in rem.overdue if i.kev]
            text = tr("{count} findings are past their deadline.", count=len(rem.overdue))
            if kev:
                refs = ", ".join(i.ref for i in kev[:3])
                text = tr("{count} findings are past their deadline; {kev} of them are known exploited "
                          "vulnerabilities ({refs}).", count=len(rem.overdue), kev=len(kev), refs=refs)
            points.append(text)
        if risk_now is not None and risk_prev is not None and round(risk_now) != round(risk_prev):
            points.append(tr("The average risk score went from {prev} to {now}.",
                             prev=round(risk_prev), now=round(risk_now)))
        if cis_now is not None:
            comp = ctx.compliance()
            worst = min(comp.values(), key=lambda s: s.compliance_pct) if comp else None
            if cis_prev is not None and round(cis_now) != round(cis_prev):
                text = tr("CIS compliance went from {prev} to {now}.", prev=tr.pct(cis_prev), now=tr.pct(cis_now))
            else:
                text = tr("CIS compliance is {now}.", now=tr.pct(cis_now))
            if worst is not None and worst.asset_id in ctx.by_id:
                text += " " + tr("Lowest: {asset} at {pct}.", asset=ctx.by_id[worst.asset_id].asset_name,
                                 pct=tr.pct(worst.compliance_pct))
            points.append(text)
        if can_cve:
            kev = [f for f in ctx.cve() if f.get("kev")]
            if kev:
                points.append(tr("{count} known exploited vulnerabilities are open on {assets} assets.",
                                 count=len(kev), assets=len({f["asset_id"] for f in kev})))
        if rem is not None and rem.accepted:
            acc = data.accepted_at(ctx.db, ctx.period.end)
            soon = [a for a in acc if a.expires_at <= ctx.period.end + timedelta(days=7)]
            text = tr("{count} findings are covered by an accepted risk.", count=len(rem.accepted))
            if soon:
                text += " " + tr("{count} acceptances end within 7 days.", count=len(soon))
            points.append(text)
        if rem is not None and rem.fixed:
            points.append(tr("{count} findings were fixed in the period, {pct} of them on time.",
                             count=len(rem.fixed), pct=tr.pct(rem.on_time_pct)))
        if points:
            blocks.append({"type": "heading", "text": tr("Key points")})
            blocks.append(bullets(points))
        if not blocks:
            blocks.append(note(tr("You have no access to the figures this summary is made of.")))
        out["summary"] = blocks

    if ctx.on("risk"):
        out["risk"] = _risk_trend_blocks(ctx) + [_top_risk_table(ctx, 5)]

    if ctx.on("compliance"):
        comp = ctx.compliance()
        prev = ctx.compliance(prev=True) if ctx.prev else {}
        rows = []
        for aid, s in sorted(comp.items(), key=lambda kv: -(kv[1].compliance_pct or 0)):
            pct = s.compliance_pct or 0
            color = "#1f8a4c" if pct >= 80 else "#d9a514" if pct >= 65 else "#e0671b"
            change = ""
            if aid in prev and round(pct) != round(prev[aid].compliance_pct or 0):
                d, _ = _delta(ctx, pct, prev[aid].compliance_pct, False, pct=True)
                change = d or ""
            rows.append({"label": ctx.by_id[aid].asset_name, "text": tr.pct(pct), "change": change,
                         "segments": [(pct, color)]})
        missing = len(ctx.ids) - len(comp)
        blocks = [bars(rows)] if rows else [note(tr("No asset in this report has a completed audit."))]
        if rows and missing:
            blocks.append(note(tr("{count} assets have no completed audit and are not shown.", count=missing)))
        out["compliance"] = blocks

    if ctx.on("vulnerabilities"):
        out["vulnerabilities"] = _cve_overview(ctx) + [_cve_table(ctx, [f for f in ctx.cve() if f["priority"] <= 2],
                                                                  10, tr("Fix first"))]

    if ctx.on("remediation"):
        out["remediation"] = [_overdue_table(ctx, ctx.remediation(), 10)]

    if ctx.on("acceptances"):
        out["acceptances"] = [_acceptance_table(ctx)]

    if ctx.on("backup"):
        out["backup"] = _backup_blocks(ctx)

    if ctx.on("appendix"):
        out["appendix"] = [_open_findings_table(ctx, ctx.remediation().open, None, sheet=tr("Open findings"))]
    return out


def _risk_trend_blocks(ctx: Ctx) -> List[dict]:
    tr = ctx.tr
    span = max(ctx.period.days, 1)
    if span <= 35:
        step, n = timedelta(days=7), 12
    elif span <= 120:
        step, n = timedelta(days=7), 16
    else:
        step, n = timedelta(days=30), 12
    trend = data.risk_trend(ctx.db, ctx.ids, ctx.period.end, n, step)
    points = [(ctx.short(at - timedelta(seconds=1)), v) for at, v in trend]
    drawn = charts.line(points, lambda v: tr.num(round(v)), label_every=max(1, n // 4))
    if not drawn[0]:
        return [note(tr("Not enough risk history to draw a trend."))]
    every = tr("week") if step.days == 7 else tr("month")
    return [chart(drawn, tr("Average risk score of the assets in this report at the end of each {step}; "
                          "lower is better.", step=every))]


def _top_risk_table(ctx: Ctx, limit: Optional[int]) -> dict:
    tr = ctx.tr
    now, prev = ctx.risk(), (ctx.risk(prev=True) if ctx.prev else {})
    comp = ctx.compliance() if ctx.can("auditing") else {}
    scores = {s.asset_id: s for s in ctx.db.query(AssetRiskScore).filter(AssetRiskScore.asset_id.in_(ctx.ids or [-1]))}
    rows = []
    for aid, score in sorted(now.items(), key=lambda kv: -kv[1])[:limit]:
        a = ctx.by_id[aid]
        d, good = _delta(ctx, score, prev.get(aid), True)
        cur = scores.get(aid)
        crit = (cur.critical_findings_count or 0) if cur else 0
        kev = (cur.cve_kev_count or 0) if cur else 0
        crit_text = tr.num(crit) + (f" (KEV {tr.num(kev)})" if kev else "")
        row = [cell(a.asset_name, cls="mono"), _num(ctx, round(score)),
               cell(d or "—", value=None, cls="up" if good else ("down" if good is False else "")),
               cell(crit_text, value=crit)]
        if ctx.can("auditing"):
            row.append(_pct(ctx, _compliance_value(comp.get(aid))))
        rows.append(row)
    cols = [col(tr("Asset"), mono=True), col(tr("Risk score"), num=True), col(tr("Change")),
            col(tr("Critical findings"))]
    if ctx.can("auditing"):
        cols.append(col(tr("CIS compliance"), num=True))
    return table(tr("Riskiest assets"), cols, rows, tr("No risk score has been calculated yet."),
                 title=tr("Riskiest assets"))


def _cve_overview(ctx: Ctx) -> List[dict]:
    tr = ctx.tr
    f = ctx.cve()
    by = data.count_by(f, lambda x: x["severity"])
    items = [kpi(tr("Findings"), tr.num(len(f))), kpi(tr("Critical"), tr.num(by.get("critical", 0))),
             kpi(tr("High"), tr.num(by.get("high", 0))),
             kpi(tr("Known exploited (KEV)"), tr.num(sum(1 for x in f if x.get("kev")))),
             kpi(tr("Affected assets"), tr.num(len({x["asset_id"] for x in f})))]
    if ctx.can("remediation"):
        rem = ctx.remediation(sources=("cve",))
        items.append(kpi(tr("Fixed in the period"), tr.num(len(rem.fixed)),
                         sub=tr("{count} new", count=len(rem.new))))
    blocks = [kpis(items)]
    from app.models.cve import CveUpdateJob
    last = (ctx.db.query(CveUpdateJob.finished_at).filter(CveUpdateJob.status == "succeeded")
            .order_by(CveUpdateJob.finished_at.desc()).first())
    if last and last[0]:
        blocks.append(note(tr("Findings are matched against the CVE database as it was when this report was "
                              "built (last updated {date}).", date=ctx.date(last[0]))))
    else:
        blocks.append(note(tr("The CVE database has not been loaded; no vulnerability can be reported.")))
    return blocks


def _cve_table(ctx: Ctx, findings: List[dict], limit: Optional[int], title: Optional[str] = None,
               sheet: Optional[str] = None) -> dict:
    tr = ctx.tr
    rows = []
    for f in findings[:limit] if limit else findings:
        rows.append([cell(f["cve_id"], cls="mono nowrap"), cell(f["asset_name"], cls="mono"),
                     cell(" ".join(x for x in (f.get("product"), f.get("installed")) if x), cls="mono"),
                     cell(f.get("fixed_in") or "—", cls="mono"),
                     _sev_cell(ctx, f.get("severity"), bool(f.get("kev"))),
                     _num(ctx, f.get("cvss"), 1),
                     _pct(ctx, (f["epss"] * 100) if f.get("epss") is not None else None)])
    cols = [col("CVE", mono=True), col(tr("Asset"), mono=True), col(tr("Product and version"), mono=True),
            col(tr("Fixed in"), mono=True), col(tr("Severity")), col("CVSS", num=True), col("EPSS", num=True)]
    return table(sheet or title or tr("Vulnerabilities"), cols, rows, tr("No vulnerability found."),
                 pdf_limit=150, title=title)


def _overdue_table(ctx: Ctx, rem: data.Remediation, limit: Optional[int]) -> dict:
    tr = ctx.tr
    names = _owner_names(ctx.db, [i.owner_id for i in rem.overdue])
    rows = [[_sev_cell(ctx, i.severity, i.kev), cell(i.ref, cls="mono"), cell(i.asset_name or "—", cls="mono"),
             cell(names.get(i.owner_id) or tr("Unassigned")), cell(ctx.date(i.due_at), value=ctx.date(i.due_at)),
             cell(_days_late(ctx, i.due_at))]
            for i in (rem.overdue[:limit] if limit else rem.overdue)]
    cols = [col(tr("Severity")), col(tr("Finding"), mono=True), col(tr("Asset"), mono=True), col(tr("Owner")),
            col(tr("Deadline")), col(tr("Late by"))]
    t = table(tr("Past the deadline"), cols, rows, tr("No finding is past its deadline."),
              title=tr("Past the deadline"))
    if limit and len(rem.overdue) > limit:
        t["more"] = tr("{count} more in the Remediation report.", count=len(rem.overdue) - limit)
    return t


def _acceptance_table(ctx: Ctx, include_all_assets: bool = False) -> dict:
    tr = ctx.tr
    acc = [a for a in data.accepted_at(ctx.db, ctx.period.end)
           if include_all_assets or a.asset_id is None or a.asset_id in ctx.ids or a.scope != "item"]
    names = _owner_names(ctx.db, [a.decided_by for a in acc] + [a.requested_by for a in acc])
    from app.models import Asset
    assets = dict(ctx.db.query(Asset.id, Asset.asset_name).filter(Asset.id.in_([a.asset_id for a in acc] or [-1])))
    rows = []
    for a in sorted(acc, key=lambda a: a.expires_at):
        where = tr("every asset") if a.scope != "item" else (assets.get(a.asset_id) or "—")
        rows.append([cell(a.ref, cls="mono"), cell(where, cls="mono" if a.scope == "item" else ""),
                     _sev_cell(ctx, a.severity, a.kev), cell(a.justification),
                     cell(a.compensating_control or "—"), cell(names.get(a.decided_by) or "—"),
                     cell(ctx.date(a.expires_at))])
    cols = [col(tr("Finding"), mono=True), col(tr("Asset")), col(tr("Severity")), col(tr("Reason")),
            col(tr("Compensating control")), col(tr("Approved by")), col(tr("Until"))]
    return table(tr("Accepted risks"), cols, rows, tr("No risk acceptance was in force."),
                 title=tr("Accepted risks"))


def _open_findings_table(ctx: Ctx, items, limit: Optional[int], sheet: str, title: Optional[str] = None) -> dict:
    tr = ctx.tr
    names = _owner_names(ctx.db, [i.owner_id for i in items])
    source = {"cve": "CVE", "audit": tr("Audit"), "arch": tr("Architecture")}
    rows = [[_sev_cell(ctx, i.severity, i.kev), cell(i.ref, cls="mono"), cell(i.title),
             cell(i.asset_name or "—", cls="mono"), cell(source.get(i.source, i.source)),
             cell(names.get(i.owner_id) or tr("Unassigned")), cell(ctx.date(i.first_seen_at)),
             cell(ctx.date(i.due_at), cls="late" if i.due_at and i.due_at < ctx.period.end else "")]
            for i in (items[:limit] if limit else items)]
    cols = [col(tr("Severity")), col(tr("Finding"), mono=True), col(tr("Description")), col(tr("Asset"), mono=True),
            col(tr("Source")), col(tr("Owner")), col(tr("First seen")), col(tr("Deadline"))]
    return table(sheet, cols, rows, tr("No open finding."), pdf_limit=120, title=title)


def _backup_blocks(ctx: Ctx) -> List[dict]:
    tr = ctx.tr
    from sqlalchemy import func
    latest = dict(ctx.db.query(DeviceBackup.asset_id, func.max(DeviceBackup.created_at))
                  .filter(DeviceBackup.asset_id.in_(ctx.ids or [-1])).group_by(DeviceBackup.asset_id).all())
    network = [a for a in ctx.assets if a.asset_type and (a.asset_type.category or "").lower() == "network"]
    rows, stale = [], 0
    for a in sorted(network, key=lambda a: latest.get(a.id) or datetime.min):
        last = latest.get(a.id)
        age = (ctx.now - last).days if last else None
        bad = last is None or age > 30
        stale += bad
        rows.append([cell(a.asset_name, cls="mono"), cell(a.ip_address or "—", cls="mono"),
                     cell(ctx.date(last) if last else tr("Never"), cls="late" if bad else ""),
                     cell(tr("{days} days", days=age) if age is not None else "—", value=age)])
    cols = [col(tr("Device"), mono=True), col("IP", mono=True), col(tr("Last backup")), col(tr("Age"))]
    return [note(tr("{count} of {total} network devices have no backup from the last 30 days. "
                    "Shown as of the time the report was built.", count=stale, total=len(network))),
            table(tr("Backups"), cols, rows, tr("No network device in this report."))]


# ── CIS compliance ───────────────────────────────────────────────────────

def _failed_results(ctx: Ctx) -> List[tuple]:
    """(session, result, hardened?) for every failed check in each asset's latest audit."""
    comp = ctx.compliance()
    sessions = {s.id: s for s in comp.values()}
    if not sessions:
        return []
    results = (ctx.db.query(AuditResult).filter(AuditResult.session_id.in_(list(sessions)),
                                                 AuditResult.status == CheckStatus.FAIL).all())
    hardened = {r for (r,) in ctx.db.query(HardeningAction.audit_result_id)
                .filter(HardeningAction.status == "success", HardeningAction.action_type != "preview",
                        HardeningAction.audit_session_id.in_(list(sessions)))}
    out = [(sessions[r.session_id], r, r.id in hardened) for r in results]
    out.sort(key=lambda x: (ctx.by_id[x[0].asset_id].asset_name, SEV_ORDER.get((x[1].severity or "").lower(), 9),
                            x[1].check_number or ""))
    return out


def _compliance(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out = ctx.tr, {}
    comp = ctx.compliance()
    prev = ctx.compliance(prev=True) if ctx.prev else {}
    failed = ctx.cached("failed", lambda: _failed_results(ctx))
    fails_by_asset = defaultdict(lambda: defaultdict(int))
    for s, r, hardened in failed:
        if not hardened:
            fails_by_asset[s.asset_id][(r.severity or "").lower()] += 1

    if ctx.on("overview"):
        avg = data.average(_compliance_value(s) for s in comp.values())
        avg_prev = data.average(_compliance_value(s) for s in prev.values()) if prev else None
        d, g = _delta(ctx, avg, avg_prev, False, pct=True)
        in_period = sum(1 for s in comp.values() if s.completed_at >= ctx.period.start)
        crit = sum(v.get("critical", 0) + v.get("high", 0) for v in fails_by_asset.values())
        out["overview"] = [kpis([
            kpi(tr("Average compliance"), tr.pct(avg) if avg is not None else "—", d, g),
            kpi(tr("Audited assets"), tr("{n} of {total}", n=len(comp), total=len(ctx.ids))),
            kpi(tr("Audited in the period"), tr.num(in_period)),
            kpi(tr("Failed critical and high checks"), tr.num(crit), sub=tr("not yet hardened")),
        ]), note(tr("Each asset counts with its latest completed audit before the end of the period."))]

    if ctx.on("by_asset"):
        rows = []
        for aid, s in sorted(comp.items(), key=lambda kv: kv[1].compliance_pct or 0):
            a = ctx.by_id[aid]
            d, good = _delta(ctx, s.compliance_pct, prev[aid].compliance_pct if aid in prev else None, False, pct=True)
            f = fails_by_asset.get(aid, {})
            rows.append([cell(a.asset_name, cls="mono"), cell(a.ip_address or "—", cls="mono"),
                         cell(_device(s.device_type)),
                         cell(ctx.date(s.completed_at)), _pct(ctx, s.compliance_pct),
                         cell(d or "—", cls="up" if good else ("down" if good is False else "")),
                         _num(ctx, f.get("critical", 0) + f.get("high", 0)), _num(ctx, sum(f.values()))])
        cols = [col(tr("Asset"), mono=True), col("IP", mono=True), col(tr("Device type")), col(tr("Last audit")),
                col(tr("Compliance"), num=True), col(tr("Change")), col(tr("Critical and high"), num=True),
                col(tr("Failed"), num=True)]
        out["by_asset"] = [table(tr("Compliance by asset"), cols, rows, tr("No asset in this report has a "
                                                                            "completed audit."))]

    if ctx.on("top_failed"):
        agg = {}
        for s, r, hardened in failed:
            if hardened:
                continue
            key = r.check_number or r.check_title
            e = agg.setdefault(key, {"r": r, "assets": set()})
            e["assets"].add(s.asset_id)
        top = sorted(agg.values(), key=lambda e: (-len(e["assets"]), SEV_ORDER.get((e["r"].severity or "").lower(), 9)))
        rows = [[cell(e["r"].check_number or "—", cls="mono"), cell(e["r"].check_title or "—"),
                 _sev_cell(ctx, (e["r"].severity or "").lower()), _num(ctx, len(e["assets"]))] for e in top[:20]]
        cols = [col(tr("Check"), mono=True), col(tr("Title")), col(tr("Severity")), col(tr("Assets failing"), num=True)]
        out["top_failed"] = [table(tr("Most common failures"), cols, rows, tr("No failed check."))]

    if ctx.on("failed_checks"):
        evidence = bool(ctx.options.get("evidence"))
        rows = []
        for s, r, hardened in failed:
            row = [cell(ctx.by_id[s.asset_id].asset_name, cls="mono"),
                   cell((r.check_number or "—") + (f" · {r.vdom}" if r.vdom and r.vdom != "global" else ""), cls="mono"),
                   cell(r.check_title or "—"), _sev_cell(ctx, (r.severity or "").lower()),
                   cell(tr("Hardened") if hardened else tr("Open"), cls="up" if hardened else "")]
            if evidence:
                row.append(cell((r.evidence_snippet or "")[:400], cls="mono small"))
            rows.append(row)
        cols = [col(tr("Asset"), mono=True), col(tr("Check"), mono=True), col(tr("Title")), col(tr("Severity")),
                col(tr("Status"))]
        if evidence:
            cols.append(col(tr("Evidence"), mono=True))
        out["failed_checks"] = [table(tr("Failed checks"), cols, rows, tr("No failed check."), pdf_limit=200)]

    if ctx.on("not_audited"):
        missing = [a for a in ctx.assets if a.id not in comp or comp[a.id].completed_at < ctx.period.start]
        rows = [[cell(a.asset_name, cls="mono"), cell(a.ip_address or "—", cls="mono"),
                 cell(a.asset_type.type_name if a.asset_type else "—"),
                 cell(ctx.date(comp[a.id].completed_at) if a.id in comp else tr("Never"))] for a in missing]
        cols = [col(tr("Asset"), mono=True), col("IP", mono=True), col(tr("Asset type")), col(tr("Last audit"))]
        out["not_audited"] = [table(tr("Not audited in the period"), cols, rows,
                                    tr("Every asset was audited in the period."))]
    return out


# ── CVE ──────────────────────────────────────────────────────────────────

def _cve(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out = ctx.tr, {}
    minimum = ctx.options.get("min_severity") or "all"
    rank = {"all": 9, "low": 3, "medium": 2, "high": 1, "critical": 0}[minimum]
    findings = [f for f in ctx.cve() if SEV_ORDER.get(f.get("severity") or "", 9) <= rank or minimum == "all"]
    if ctx.options.get("kev_only"):
        findings = [f for f in findings if f.get("kev")]
    ctx._cache["cve"] = findings

    if ctx.on("overview"):
        out["overview"] = _cve_overview(ctx)
    if ctx.on("fix_first"):
        out["fix_first"] = [_cve_table(ctx, [f for f in findings if f["priority"] <= 2], None, sheet=tr("Fix first"))]
    if ctx.on("by_asset"):
        per = defaultdict(lambda: defaultdict(int))
        for f in findings:
            per[f["asset_id"]][f.get("severity") or "none"] += 1
            if f.get("kev"):
                per[f["asset_id"]]["kev"] += 1
        rows = [[cell(ctx.by_id[aid].asset_name, cls="mono"), cell(ctx.by_id[aid].ip_address or "—", cls="mono"),
                 _num(ctx, c.get("critical", 0)), _num(ctx, c.get("high", 0)), _num(ctx, c.get("medium", 0)),
                 _num(ctx, c.get("low", 0)), _num(ctx, c.get("kev", 0))]
                for aid, c in sorted(per.items(), key=lambda kv: (-kv[1].get("kev", 0), -kv[1].get("critical", 0),
                                                                   -sum(v for k, v in kv[1].items() if k != "kev")))]
        cols = [col(tr("Asset"), mono=True), col("IP", mono=True), col(tr("Critical"), num=True),
                col(tr("High"), num=True), col(tr("Medium"), num=True), col(tr("Low"), num=True),
                col("KEV", num=True)]
        out["by_asset"] = [table(tr("By asset"), cols, rows, tr("No vulnerability found."))]
    if ctx.on("all_findings"):
        out["all_findings"] = [_cve_table(ctx, findings, None, sheet=tr("All findings"))]
    return out


# ── asset risk ───────────────────────────────────────────────────────────

FACTORS = (("criticality_contribution", "Criticality"), ("asset_risk_contribution", "Asset value"),
           ("zone_contribution", "Network zone"), ("open_port_contribution", "Open ports"),
           ("audit_contribution", "Audit findings"), ("hardening_contribution", "Hardening"),
           ("vulnerability_contribution", "Vulnerabilities"))
LEVELS = (("critical", "Critical", "#c0262d"), ("high", "High", "#e0671b"), ("medium", "Medium", "#d9a514"),
          ("low", "Low", "#9aa6b8"), ("informational", "Informational", "#cfd6e1"))


def _level(score: float) -> str:
    from app.modules.risk.levels import risk_level_for_score
    return risk_level_for_score(score)


def _risk(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out = ctx.tr, {}
    now = ctx.risk()
    prev = ctx.risk(prev=True) if ctx.prev else {}
    scores = {s.asset_id: s for s in ctx.db.query(AssetRiskScore).filter(AssetRiskScore.asset_id.in_(ctx.ids or [-1]))}

    if ctx.on("overview"):
        avg, avg_prev = data.average(now.values()), data.average(prev.values()) if prev else None
        d, g = _delta(ctx, avg, avg_prev, True)
        levels = data.count_by(now.values(), _level)
        out["overview"] = [kpis([
            kpi(tr("Average risk score"), tr.num(avg) if avg is not None else "—", d, g),
            kpi(tr("Critical"), tr.num(levels.get("critical", 0))), kpi(tr("High"), tr.num(levels.get("high", 0))),
            kpi(tr("Assets without a score"), tr.num(len(ctx.ids) - len(now))),
        ])]
        total = len(now) or 1
        rows = [{"label": tr(label), "text": tr.num(levels.get(key, 0)), "change": "",
                 "segments": [(100 * levels.get(key, 0) / total, color)]} for key, label, color in LEVELS]
        out["overview"].append(bars(rows, mono_labels=False))
    if ctx.on("trend"):
        out["trend"] = _risk_trend_blocks(ctx)
    if ctx.on("by_asset"):
        rows = []
        for aid, score in sorted(now.items(), key=lambda kv: -kv[1]):
            a, cur = ctx.by_id[aid], scores.get(aid)
            d, good = _delta(ctx, score, prev.get(aid), True)
            factor = "—"
            if cur is not None:
                best = max(FACTORS, key=lambda f: float(getattr(cur, f[0]) or 0))
                if float(getattr(cur, best[0]) or 0) > 0:
                    factor = tr(best[1])
            rows.append([cell(a.asset_name, cls="mono"), _num(ctx, round(score)),
                         cell(tr.severity(_level(score)), value=_level(score)),
                         cell(d or "—", cls="up" if good else ("down" if good is False else "")), cell(factor),
                         _num(ctx, cur.cve_findings_count if cur else None), _num(ctx, cur.cve_kev_count if cur else None)])
        cols = [col(tr("Asset"), mono=True), col(tr("Risk score"), num=True), col(tr("Level")), col(tr("Change")),
                col(tr("Largest factor")), col("CVE", num=True), col("KEV", num=True)]
        out["by_asset"] = [table(tr("Risk by asset"), cols, rows, tr("No risk score has been calculated yet."))]
    if ctx.on("factors"):
        rows = []
        for attr, label in FACTORS:
            vals = [float(getattr(s, attr)) for s in scores.values() if getattr(s, attr) is not None]
            rows.append([cell(tr(label)), _num(ctx, round(sum(vals) / len(vals), 1) if vals else None, 1)])
        out["factors"] = [table(tr("Risk factors"), [col(tr("Factor")), col(tr("Average contribution"), num=True)],
                                rows, tr("No risk score has been calculated yet.")),
                          note(tr("Average points each factor adds to the risk score, from the current scores."))]
    return out


# ── remediation ──────────────────────────────────────────────────────────

def _remediation(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out = ctx.tr, {}
    sources = [s for s in (ctx.options.get("sources") or []) if s in ("cve", "audit", "arch")] or None
    rem = ctx.remediation(sources=sources)
    prev = (data.remediation(ctx.db, ctx.ids, ctx.prev.start, ctx.prev.end, sources) if ctx.prev else None)

    if ctx.on("overview"):
        def dl(cur, old, lower=True, **kw):
            return _delta(ctx, cur, old, lower, **kw)
        d1 = dl(len(rem.open), len(prev.open) if prev else None)
        d2 = dl(len(rem.overdue), len(prev.overdue) if prev else None)
        d3 = dl(rem.on_time_pct, prev.on_time_pct if prev else None, False, pct=True)
        d4 = dl(rem.mttr_days, prev.mttr_days if prev else None, True, decimals=1, unit=" " + tr("days"))
        out["overview"] = [kpis([
            kpi(tr("Open findings"), tr.num(len(rem.open)), *d1),
            kpi(tr("Past the deadline"), tr.num(len(rem.overdue)), *d2),
            kpi(tr("Fixed in the period"), tr.num(len(rem.fixed)), sub=tr("{count} new", count=len(rem.new))),
            kpi(tr("Fixed on time"), tr.pct(rem.on_time_pct) if rem.on_time_pct is not None else "—", *d3),
            kpi(tr("Average time to fix"),
                tr("{days} days", days=round(rem.mttr_days, 1)) if rem.mttr_days is not None else "—", *d4),
            kpi(tr("Risk accepted"), tr.num(len(rem.accepted))),
        ])]
    if ctx.on("by_owner"):
        names = _owner_names(ctx.db, [i.owner_id for i in rem.open + rem.fixed])
        agg = defaultdict(lambda: {"open": 0, "overdue": 0, "fixed": 0, "on_time": 0})
        overdue_ids = {i.id for i in rem.overdue}
        for i in rem.open:
            agg[i.owner_id]["open"] += 1
            agg[i.owner_id]["overdue"] += i.id in overdue_ids
        for i in rem.fixed:
            agg[i.owner_id]["fixed"] += 1
            agg[i.owner_id]["on_time"] += i.due_at is None or i.resolved_at <= i.due_at
        rows = [[cell(names.get(o) or tr("Unassigned")), _num(ctx, v["open"]), _num(ctx, v["overdue"]),
                 _num(ctx, v["fixed"]), _pct(ctx, 100 * v["on_time"] / v["fixed"] if v["fixed"] else None)]
                for o, v in sorted(agg.items(), key=lambda kv: (-kv[1]["overdue"], -kv[1]["open"]))]
        cols = [col(tr("Owner")), col(tr("Open"), num=True), col(tr("Past the deadline"), num=True),
                col(tr("Fixed in the period"), num=True), col(tr("Fixed on time"), num=True)]
        out["by_owner"] = [table(tr("By owner"), cols, rows, tr("No finding in the period."))]
    if ctx.on("overdue"):
        out["overdue"] = [_overdue_table(ctx, rem, None)]
    if ctx.on("by_severity"):
        source = (("cve", "CVE"), ("audit", tr("Audit")), ("arch", tr("Architecture")))
        counts = data.count_by(rem.open, lambda i: (i.source, i.severity))
        rows = [[cell(label)] + [_num(ctx, counts.get((key, s), 0)) for s in ("critical", "high", "medium", "low")]
                + [_num(ctx, sum(counts.get((key, s), 0) for s in ("critical", "high", "medium", "low")))]
                for key, label in source if not sources or key in sources]
        cols = [col(tr("Source")), col(tr("Critical"), num=True), col(tr("High"), num=True),
                col(tr("Medium"), num=True), col(tr("Low"), num=True), col(tr("Total"), num=True)]
        out["by_severity"] = [table(tr("Open by source and severity"), cols, rows, tr("No open finding."))]
    if ctx.on("acceptances"):
        out["acceptances"] = [_acceptance_table(ctx)]
    if ctx.on("open_list"):
        out["open_list"] = [_open_findings_table(ctx, rem.open, None, sheet=tr("Open findings"))]
    if ctx.on("fixed"):
        rows = [[_sev_cell(ctx, i.severity, i.kev), cell(i.ref, cls="mono"), cell(i.asset_name or "—", cls="mono"),
                 cell(ctx.date(i.first_seen_at)), cell(ctx.date(i.resolved_at)),
                 cell(tr("On time") if i.due_at is None or i.resolved_at <= i.due_at else tr("Late"),
                      cls="up" if i.due_at is None or i.resolved_at <= i.due_at else "down")]
                for i in sorted(rem.fixed, key=lambda i: i.resolved_at)]
        cols = [col(tr("Severity")), col(tr("Finding"), mono=True), col(tr("Asset"), mono=True), col(tr("First seen")),
                col(tr("Fixed")), col(tr("Status"))]
        out["fixed"] = [table(tr("Fixed in the period"), cols, rows, tr("Nothing was fixed in the period."),
                              pdf_limit=100)]
    return out


# ── registry ─────────────────────────────────────────────────────────────

SEVERITY_CHOICES = (("all", "All"), ("medium", "Medium and above"), ("high", "High and above"),
                    ("critical", "Critical only"))

TEMPLATES: Dict[str, Template] = {t.id: t for t in (
    Template("executive", "Security executive summary",
             "Risk score and its trend, compliance, critical vulnerabilities, fixing on time and exceptions; "
             "with key points and a comparison with the previous period.",
             "management", None, sections=[
                 Section("summary", "Summary and key points", None, "Figures and sentences drawn from the data"),
                 Section("risk", "Risk score trend", "risk", "Weekly, with the riskiest assets"),
                 Section("compliance", "CIS compliance", "auditing", "By asset"),
                 Section("vulnerabilities", "Vulnerabilities", "cve", "Critical and known exploited"),
                 Section("remediation", "Remediation and deadlines", "remediation", "Findings past their deadline"),
                 Section("acceptances", "Accepted risks", "remediation", "Exceptions in force"),
                 Section("backup", "Backups", "backup", "Devices without a recent backup", default=False),
                 Section("appendix", "Appendix: every open finding", "remediation", "As a separate Excel file",
                         default=False, excel_only=True),
             ], build=_executive),
    Template("cis_compliance", "CIS compliance",
             "Pass rate of each asset and each part of the benchmark, failed checks with evidence, and the change "
             "since the previous audit.",
             "audit", "auditing", sections=[
                 Section("overview", "Overview", "auditing"),
                 Section("by_asset", "Compliance by asset", "auditing"),
                 Section("top_failed", "Most common failures", "auditing"),
                 Section("failed_checks", "Failed checks", "auditing", "Every failed check of each asset"),
                 Section("not_audited", "Not audited in the period", "auditing"),
             ], options=[Option("evidence", "Include the evidence of each failed check", "bool", False)],
             build=_compliance),
    Template("cve", "Vulnerabilities (CVE)",
             "Findings by asset and product, known exploited ones (KEV) and the chance of exploitation (EPSS).",
             "vulnerability", "cve", sections=[
                 Section("overview", "Overview", "cve"),
                 Section("fix_first", "Fix first", "cve", "Known exploited, CVSS 9+ or EPSS 50%+"),
                 Section("by_asset", "By asset", "cve"),
                 Section("all_findings", "All findings", "cve"),
             ], options=[Option("min_severity", "Severity", "choice", "all", SEVERITY_CHOICES),
                         Option("kev_only", "Only known exploited (KEV)", "bool", False)],
             default_period="last_30_days", build=_cve),
    Template("risk", "Asset risk",
             "Risk score of each asset, the factors behind it and its trend over the period.",
             "vulnerability", "risk", sections=[
                 Section("overview", "Overview", "risk"),
                 Section("trend", "Trend", "risk"),
                 Section("by_asset", "Risk by asset", "risk"),
                 Section("factors", "Risk factors", "risk"),
             ], build=_risk),
    Template("remediation", "Remediation and accepted risks",
             "Fixing on time, findings past their deadline by owner, and the list of exceptions with reason "
             "and approver.",
             "vulnerability", "remediation", sections=[
                 Section("overview", "Overview", "remediation"),
                 Section("by_owner", "By owner", "remediation"),
                 Section("overdue", "Past the deadline", "remediation"),
                 Section("by_severity", "Open by source and severity", "remediation"),
                 Section("acceptances", "Accepted risks", "remediation"),
                 Section("fixed", "Fixed in the period", "remediation", default=False),
                 Section("open_list", "Every open finding", "remediation", default=False),
             ], options=[Option("sources", "Sources", "multi", [], (("cve", "CVE"), ("audit", "Audit"),
                                                                     ("arch", "Architecture")))],
             build=_remediation),
)}

# Templates shown in the catalog that cannot be built yet.
PLANNED: tuple = ()

# The second set lives in templates2.py, which builds on the helpers above.
from app.modules.reports.templates2 import PHASE2  # noqa: E402

TEMPLATES.update({t.id: t for t in PHASE2})
