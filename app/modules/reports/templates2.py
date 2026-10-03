"""
Report templates, second set: audit details, hardening changes, assets and
coverage, backup and restore, availability (NOC), architecture validation,
alerts, user activity and software inventory.

Same building blocks as app/modules/reports/templates.py. Nothing a device
returned in full is printed: audits show only the short, redacted evidence
of each check, hardening shows the commands with secrets masked, and no
configuration content ever appears in a report.
"""
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func

from app.models.audit import AuditResult, AuditSession, AuditTemplate, CheckStatus
from app.models.backup import DeviceBackup
from app.models.hardening import HardeningAction
from app.modules.reports import data
from app.modules.reports.templates import (SEV_ORDER, Ctx, Option, Section, Template, _device, _num, _owner_names,
                                           _pct, _sev_cell, bars, cell, col, kpi, kpis, note, table)

GREEN, YELLOW, RED, GREY = "#2f9e5b", "#d9a514", "#c0262d", "#cfd6e1"


def _heading(text: str) -> dict:
    return {"type": "heading", "text": text}


def _name(ctx: Ctx, asset_id) -> str:
    a = ctx.by_id.get(asset_id)
    return a.asset_name if a else "—"


def _dt(ctx: Ctx, when: Optional[datetime]) -> str:
    """Short date and local time: "12 Mehr 14:05"."""
    if when is None:
        return "—"
    from app.modules.reports.calendar import fa_digits
    if when.tzinfo is not None:
        when = when.astimezone(timezone.utc).replace(tzinfo=None)
    local = ctx.local(when)
    hm = f"{local:%H:%M}"
    return f"{ctx.short(when)} {fa_digits(hm) if ctx.lang == 'fa' else hm}"


def _ago(ctx: Ctx, when: Optional[datetime]) -> Optional[int]:
    return (ctx.now - when).days if when else None


def _duration(ctx: Ctx, seconds: float) -> str:
    tr = ctx.tr
    minutes = int(round(seconds / 60))
    if minutes < 60:
        return tr("{m} min", m=max(minutes, 1) if seconds > 0 else 0)
    hours, rest = divmod(minutes, 60)
    if hours < 48:
        return tr("{h} h {m} min", h=hours, m=rest) if rest else tr("{h} h", h=hours)
    return tr("{d} days {h} h", d=hours // 24, h=hours % 24)


_SECRET = re.compile(r"(?i)\b(password|secret|community|key-string|key|pre-shared-key|psk|passwd|"
                     r"snmp-server community)(\s+(?:\d\s+)?)(\S+)")


def _mask(text: str) -> str:
    """Commands as they were sent, with anything that looks like a secret masked."""
    return _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}********", text or "")


# ── audit details ────────────────────────────────────────────────────────

AUDIT_MODES = (("latest", "Latest audit of each asset"), ("session", "One audit"))


def _audit_sessions(ctx: Ctx) -> List[AuditSession]:
    from app.modules.reports.service import ReportError
    if ctx.options.get("audit_mode") == "session":
        s = ctx.db.get(AuditSession, ctx.options.get("audit_session") or 0)
        if s is None or s.status != "completed":
            raise ReportError("The audit this report describes was not found or did not complete")
        if s.asset_id and s.asset_id not in ctx.by_id:
            from app.models import Asset
            a = ctx.db.get(Asset, s.asset_id)
            if a is not None:
                ctx.by_id[a.id] = a
        when = ctx.local(s.completed_at)
        ctx.header_line = ctx.tr("Audit {id} of {asset} · {date}", id=f"#{s.id}",
                                 asset=_name(ctx, s.asset_id) if s.asset_id else s.target_ip,
                                 date=ctx.date(when) if when else "—")
        ctx.scope_line = ""                 # the line above already names the asset
        return [s]
    latest = data.compliance_at(ctx.db, ctx.ids, ctx.now + timedelta(seconds=1))
    ctx.header_line = ctx.tr("Latest audit of each asset, as of {date}", date=ctx.date(ctx.now))
    return sorted(latest.values(), key=lambda s: _name(ctx, s.asset_id))


def _audit(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out, db = ctx.tr, {}, ctx.db
    sessions = _audit_sessions(ctx)
    multi = len(sessions) > 1
    ids = [s.id for s in sessions]
    results = defaultdict(list)
    for r in db.query(AuditResult).filter(AuditResult.session_id.in_(ids or [-1])).all():
        results[r.session_id].append(r)
    from app.modules.reports.rule_text import text_for
    device = {s.id: s.device_type for s in sessions}
    templates = {t.id: t for t in db.query(AuditTemplate).filter(
        AuditTemplate.id.in_({s.template_id for s in sessions if s.template_id} or {-1}))}
    users = _owner_names(db, {s.user_id for s in sessions})
    order = lambda r: (SEV_ORDER.get((r.severity or "").lower(), 9), r.check_number or "")  # noqa: E731

    def asset_cell(s):
        return cell(_name(ctx, s.asset_id) if s.asset_id else s.target_ip, cls="mono nowrap")

    def guide(s, r):
        return text_for(device[s.id], r.check_number)

    def check_text(r):
        return (r.check_number or "—") + (f" · {r.vdom}" if r.vdom and r.vdom != "global" else "")

    if ctx.on("summary"):
        blocks = []
        if not sessions:
            blocks.append(note(tr("No asset in this report has a completed audit.")))
        elif not multi:
            s = sessions[0]
            rs = results[s.id]
            failed = [r for r in rs if r.status == CheckStatus.FAIL]
            hi = sum(1 for r in failed if (r.severity or "").lower() in ("critical", "high"))
            tpl = templates.get(s.template_id)
            blocks += [kpis([
                kpi(tr("Compliance"), tr.pct(s.compliance_pct) if s.compliance_pct is not None else "—",
                    sub=tr("weighted {pct}", pct=tr.pct(s.weighted_compliance_pct))
                    if s.weighted_compliance_pct is not None else ""),
                kpi(tr("Passed"), tr.num(sum(1 for r in rs if r.status == CheckStatus.PASS))),
                kpi(tr("Failed"), tr.num(len(failed)), sub=tr("{count} critical or high", count=hi)),
                kpi(tr("Error or not applicable"), tr.num(sum(1 for r in rs if r.status in (CheckStatus.ERROR,
                                                                                         CheckStatus.NOT_APPLICABLE)))),
            ]), table(tr("Audit"), [col(tr("Item")), col(tr("Value"))], [
                [cell(tr("Asset")), asset_cell(s)],
                [cell("IP"), cell(s.target_ip or "—", cls="mono")],
                [cell(tr("Benchmark")), cell(f"{tpl.name}{' · ' + tpl.profile if tpl and tpl.profile else ''}"
                                             if tpl else _device(s.device_type))],
                [cell(tr("Audit")), cell(f"#{s.id}", cls="mono")],
                [cell(tr("Completed")), cell(ctx.date(s.completed_at))],
                [cell(tr("Run by")), cell(users.get(s.user_id, "—"))],
            ], "")]
        else:
            rows = []
            for s in sessions:
                rs = results[s.id]
                tpl = templates.get(s.template_id)
                rows.append([asset_cell(s), cell(tpl.name if tpl else _device(s.device_type)),
                             cell(ctx.date(s.completed_at)), _pct(ctx, s.compliance_pct),
                             _num(ctx, sum(1 for r in rs if r.status == CheckStatus.PASS)),
                             _num(ctx, sum(1 for r in rs if r.status == CheckStatus.FAIL)),
                             _num(ctx, sum(1 for r in rs if r.status == CheckStatus.ERROR))])
            avg = data.average(s.compliance_pct for s in sessions if s.compliance_pct is not None)
            blocks += [kpis([kpi(tr("Audited assets"), tr.num(len(sessions))),
                             kpi(tr("Average compliance"), tr.pct(avg) if avg is not None else "—"),
                             kpi(tr("Failed checks"), tr.num(sum(1 for s in sessions for r in results[s.id]
                                                                  if r.status == CheckStatus.FAIL)))]),
                       table(tr("Audits"), [col(tr("Asset"), mono=True), col(tr("Benchmark")), col(tr("Completed")),
                                            col(tr("Compliance"), num=True), col(tr("Passed"), num=True),
                                            col(tr("Failed"), num=True), col(tr("Errors"), num=True)], rows, "")]
        out["summary"] = blocks

    guidance = bool(ctx.options.get("guidance", True))

    if ctx.on("failed"):
        rows = []
        for s in sessions:
            for r in sorted((r for r in results[s.id] if r.status == CheckStatus.FAIL), key=order):
                row = ([asset_cell(s)] if multi else []) + [
                    cell(check_text(r), cls="mono nowrap"), cell(r.check_title or "—"),
                    _sev_cell(ctx, (r.severity or "").lower()),
                    cell((r.evidence_snippet or "—")[:500], cls="mono small")]
                if guidance:
                    row.append(cell((guide(s, r)[1] or "—")[:500], cls="mono small"))
                rows.append(row)
        cols = ([col(tr("Asset"), mono=True)] if multi else []) + [
            col(tr("Check"), mono=True), col(tr("Title")), col(tr("Severity")), col(tr("Evidence"), mono=True)]
        if guidance:
            cols.append(col(tr("How to fix")))
        out["failed"] = [table(tr("Failed checks"), cols, rows, tr("No failed check."), pdf_limit=300)]
        if guidance:
            why = []
            for s in sessions:
                for r in sorted((r for r in results[s.id] if r.status == CheckStatus.FAIL), key=order):
                    rationale = guide(s, r)[0]
                    if rationale:
                        why.append(([asset_cell(s)] if multi else []) + [cell(check_text(r), cls="mono nowrap"),
                                                                         cell(rationale[:600], cls="small")])
            if why:
                out["failed"].append(table(tr("Why each failed check matters"),
                                           ([col(tr("Asset"), mono=True)] if multi else [])
                                           + [col(tr("Check"), mono=True), col(tr("Rationale"))], why, "",
                                           pdf_limit=300, title=tr("Why each failed check matters")))

    if ctx.on("errors"):
        rows = []
        for s in sessions:
            for r in sorted((r for r in results[s.id] if r.status in (CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE)),
                            key=order):
                rows.append(([asset_cell(s)] if multi else []) + [
                    cell(check_text(r), cls="mono nowrap"), cell(r.check_title or "—"),
                    cell(tr("Error") if r.status == CheckStatus.ERROR else tr("Not applicable")),
                    cell((r.evidence_snippet or "—")[:300], cls="mono small")])
        cols = ([col(tr("Asset"), mono=True)] if multi else []) + [
            col(tr("Check"), mono=True), col(tr("Title")), col(tr("Result")), col(tr("Evidence"), mono=True)]
        out["errors"] = [note(tr("A check with an error could not be evaluated, usually for lack of a permission or "
                                 "a command the device does not support; it needs to be checked by hand.")),
                         table(tr("Errors and not applicable"), cols, rows, tr("Every check could be evaluated."),
                               pdf_limit=200)]

    if ctx.on("passed"):
        rows = []
        for s in sessions:
            for r in sorted((r for r in results[s.id] if r.status == CheckStatus.PASS), key=order):
                rows.append(([asset_cell(s)] if multi else []) + [
                    cell(check_text(r), cls="mono nowrap"), cell(r.check_title or "—"),
                    _sev_cell(ctx, (r.severity or "").lower())])
        cols = ([col(tr("Asset"), mono=True)] if multi else []) + [
            col(tr("Check"), mono=True), col(tr("Title")), col(tr("Severity"))]
        out["passed"] = [table(tr("Passed checks"), cols, rows, tr("No check passed."), pdf_limit=400)]

    if ctx.on("compare"):
        rows = []
        for s in sessions:
            prev = (db.query(AuditSession).filter(AuditSession.asset_id == s.asset_id,
                                                  AuditSession.device_type == s.device_type,
                                                  AuditSession.status == "completed",
                                                  AuditSession.completed_at < s.completed_at)
                    .order_by(AuditSession.completed_at.desc()).first()) if s.asset_id else None
            if prev is None:
                continue
            before = {check_text(r): r.status for r in db.query(AuditResult).filter(AuditResult.session_id == prev.id)}
            for r in sorted(results[s.id], key=order):
                was = before.get(check_text(r))
                if was == CheckStatus.PASS and r.status == CheckStatus.FAIL:
                    change, cls = tr("Now failing"), "late"
                elif was == CheckStatus.FAIL and r.status == CheckStatus.PASS:
                    change, cls = tr("Now passing"), "up"
                else:
                    continue
                rows.append(([asset_cell(s)] if multi else []) + [
                    cell(check_text(r), cls="mono nowrap"), cell(r.check_title or "—"),
                    _sev_cell(ctx, (r.severity or "").lower()), cell(change, cls=cls),
                    cell(ctx.date(prev.completed_at))])
        cols = ([col(tr("Asset"), mono=True)] if multi else []) + [
            col(tr("Check"), mono=True), col(tr("Title")), col(tr("Severity")), col(tr("Change")),
            col(tr("Previous audit"))]
        out["compare"] = [table(tr("Change since the previous audit"), cols, rows,
                                tr("No check changed since the previous audit, or there is no previous audit."))]
    return out


# ── hardening changes ────────────────────────────────────────────────────

def _hardening(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out, db = ctx.tr, {}, ctx.db
    acts = (db.query(HardeningAction)
            .filter(HardeningAction.action_type != "preview", HardeningAction.asset_id.in_(ctx.ids or [-1]),
                    HardeningAction.created_at >= ctx.period.start, HardeningAction.created_at < ctx.period.end,
                    HardeningAction.status.in_(("success", "failed")))
            .order_by(HardeningAction.created_at).all())
    # The backup taken before a hardening run is not linked to each change: take the
    # latest backup of the same device from the two hours before the change.
    device_backups = defaultdict(list)
    for b in (db.query(DeviceBackup.id, DeviceBackup.asset_id, DeviceBackup.created_at, DeviceBackup.hardening_action_id)
              .filter(DeviceBackup.asset_id.in_({a.asset_id for a in acts} or {-1}),
                      DeviceBackup.created_at >= ctx.period.start - timedelta(hours=2),
                      DeviceBackup.created_at < ctx.period.end).order_by(DeviceBackup.created_at)):
        device_backups[b.asset_id].append(b)
    backups = {}
    for a in acts:
        when = a.executed_at or a.created_at
        linked = [b for b in device_backups[a.asset_id] if b.hardening_action_id == a.id]
        before = [b for b in device_backups[a.asset_id] if when - timedelta(hours=2) <= b.created_at <= when]
        if linked or before:
            backups[a.id] = (linked or before)[-1:]
    users = _owner_names(db, {a.user_id for a in acts})
    ok = [a for a in acts if a.status == "success"]
    failed = [a for a in acts if a.status != "success"]

    def backup_cell(a):
        bs = backups.get(a.id)
        if bs:
            b = bs[0]
            return cell(f"#{b.id} · {ctx.short(b.created_at)}", value=f"#{b.id}", cls="nowrap")
        if a.backup_config:
            return cell(tr("Kept with the change"))
        return cell("—")

    def result_cell(a):
        if a.status == "success":
            if a.verification_passed:
                return cell(tr("Succeeded · verified"), cls="up")
            if a.verification_passed is False:
                return cell(tr("Succeeded · check still fails"), cls="late")
            return cell(tr("Succeeded"), cls="up")
        return cell(tr("Failed"), cls="late")

    if ctx.on("overview"):
        with_backup = sum(1 for a in acts if backups.get(a.id) or a.backup_config)
        out["overview"] = [kpis([
            kpi(tr("Changes"), tr.num(len(acts)), sub=tr("on {count} assets", count=len({a.asset_id for a in acts}))),
            kpi(tr("Succeeded"), tr.num(len(ok)),
                sub=tr("{count} verified by a new check", count=sum(1 for a in ok if a.verification_passed))),
            kpi(tr("Failed"), tr.num(len(failed))),
            kpi(tr("With a backup taken before"), tr("{n} of {total}", n=with_backup, total=len(acts))),
        ]), note(tr("The configuration saved before each change is kept in NGCorion; for security its content is "
                    "never printed in a report."))]

    if ctx.on("by_asset"):
        per = defaultdict(list)
        for a in acts:
            per[a.asset_id].append(a)
        rows = [[cell(_name(ctx, aid), cls="mono"), _num(ctx, len(xs)),
                 _num(ctx, sum(1 for a in xs if a.status == "success")),
                 _num(ctx, sum(1 for a in xs if a.status != "success")),
                 _num(ctx, sum(1 for a in xs if a.verification_passed)), cell(ctx.date(xs[-1].created_at))]
                for aid, xs in sorted(per.items(), key=lambda kv: -len(kv[1]))]
        out["by_asset"] = [table(tr("By asset"), [col(tr("Asset"), mono=True), col(tr("Changes"), num=True),
                                                  col(tr("Succeeded"), num=True), col(tr("Failed"), num=True),
                                                  col(tr("Verified"), num=True), col(tr("Last change"))],
                                 rows, tr("No change in the period."))]

    commands = bool(ctx.options.get("commands", True))
    if ctx.on("changes"):
        rows = []
        for a in acts:
            row = [cell(_dt(ctx, a.executed_at or a.created_at), cls="nowrap"),
                   cell(_name(ctx, a.asset_id), cls="mono nowrap"),
                   cell(a.check_number + (f" · {a.target_vdom}" if a.target_vdom else ""), cls="mono nowrap"),
                   cell(a.check_title or "—"), cell(users.get(a.user_id, "—")), result_cell(a), backup_cell(a)]
            if commands:
                try:
                    cmds = json.loads(a.commands_json or "[]")
                except ValueError:
                    cmds = []
                text = "\n".join(c if isinstance(c, str) else str(c.get("command") or c.get("cmd") or "")
                                 for c in cmds)
                row.append(cell(_mask(text)[:600] or "—", cls="mono small"))
            rows.append(row)
        cols = [col(tr("Time")), col(tr("Asset"), mono=True), col(tr("Check"), mono=True), col(tr("Title")),
                col(tr("User")), col(tr("Result")), col(tr("Backup before"))]
        if commands:
            cols.append(col(tr("Commands"), mono=True))
        out["changes"] = [table(tr("Every change"), cols, rows, tr("No change in the period."), pdf_limit=250)]

    if ctx.on("failed"):
        rows = [[cell(_dt(ctx, a.executed_at or a.created_at), cls="nowrap"),
                 cell(_name(ctx, a.asset_id), cls="mono nowrap"), cell(a.check_number, cls="mono nowrap"), cell(a.check_title or "—"), cell(users.get(a.user_id, "—")),
                 cell((a.error_message or a.verification_evidence or "—")[:300], cls="small")] for a in failed]
        out["failed"] = [table(tr("Failed changes"), [col(tr("Time")), col(tr("Asset"), mono=True),
                                                      col(tr("Check"), mono=True), col(tr("Title")), col(tr("User")),
                                                      col(tr("Error"))], rows, tr("No change failed."))]
    return out


# ── assets and coverage ──────────────────────────────────────────────────

OK, OLD, MISSING, NA = "ok", "old", "missing", "na"


def _monitored_ids(db, ids) -> set:
    """Assets NOC polls: those with SNMP settings or a poll result."""
    from app.models.noc import AssetSnmpCredential, AssetSnmpStatus
    return ({aid for (aid,) in db.query(AssetSnmpCredential.asset_id).filter(AssetSnmpCredential.asset_id.in_(ids))}
            | {aid for (aid,) in db.query(AssetSnmpStatus.asset_id).filter(AssetSnmpStatus.asset_id.in_(ids))})


def _coverage_rows(ctx: Ctx) -> Dict[int, Dict[str, Tuple[str, str]]]:
    """{asset id: {control: (state, text)}} as of now."""
    from app.models.software import SoftwareCollection
    tr, db = ctx.tr, ctx.db
    days = int(ctx.options.get("audit_days") or 90)
    ids = list(ctx.ids) or [-1]
    audits = dict(db.query(AuditSession.asset_id, func.max(AuditSession.completed_at))
                  .filter(AuditSession.asset_id.in_(ids), AuditSession.status == "completed")
                  .group_by(AuditSession.asset_id).all())
    backups = dict(db.query(DeviceBackup.asset_id, func.max(DeviceBackup.created_at))
                   .filter(DeviceBackup.asset_id.in_(ids)).group_by(DeviceBackup.asset_id).all())
    snmp = _monitored_ids(db, ids)
    software = dict(db.query(SoftwareCollection.asset_id, func.max(SoftwareCollection.collected_at))
                    .filter(SoftwareCollection.asset_id.in_(ids), SoftwareCollection.status == "ok")
                    .group_by(SoftwareCollection.asset_id).all())

    def aged(when, limit):
        if when is None:
            return MISSING, tr("Never")
        age = _ago(ctx, when)
        return (OK if age <= limit else OLD), (tr("{days} days ago", days=age) if age else tr("Today"))

    out = {}
    for a in ctx.assets:
        network = bool(a.asset_type and (a.asset_type.category or "").lower() == "network")
        out[a.id] = {
            "audit": aged(audits.get(a.id), days),
            "backup": aged(backups.get(a.id), 30) if network else (NA, tr("Not needed")),
            "monitoring": (OK, tr("SNMP")) if a.id in snmp else (MISSING, tr("Not monitored")),
            "software": aged(software.get(a.id), days),
            "owner": (OK, tr("Assigned")) if a.owner_id else (MISSING, tr("No owner")),
        }
    return out


CONTROLS = (("audit", "Audit"), ("backup", "Configuration backup"), ("monitoring", "Monitoring (NOC)"),
            ("software", "Software list"), ("owner", "Owner"))


def _coverage(ctx: Ctx) -> Dict[str, List[dict]]:
    tr, out = ctx.tr, {}
    days = int(ctx.options.get("audit_days") or 90)
    cov = ctx.cached("coverage", lambda: _coverage_rows(ctx))
    ctx.header_line = tr("As of {date} · an audit or software list counts as recent within {days} days",
                         date=ctx.date(ctx.now), days=days)

    def state_cell(st):
        state, text = st
        return cell(text, value=text, cls={OK: "up", OLD: "late", MISSING: "late", NA: ""}[state])

    def share(key):
        rows = [r[key] for r in cov.values() if r[key][0] != NA]
        return sum(1 for r in rows if r[0] == OK), len(rows)

    if ctx.on("overview"):
        items, rows = [], []
        for key, label in CONTROLS:
            good, total = share(key)
            pct = 100 * good / total if total else None
            items.append(kpi(tr(label), tr.pct(pct) if pct is not None else "—",
                             sub=tr("{n} of {total}", n=good, total=total)))
            if total:
                rows.append({"label": tr(label), "text": tr.pct(pct),
                             "segments": [(pct, GREEN), (100 - pct, RED)]})
        out["overview"] = [kpis(items[:4]), bars(rows, mono_labels=False),
                           note(tr("A configuration backup is needed only for network devices; it counts as recent "
                                   "within 30 days, like on the backup page."))]

    head = [col(tr("Asset"), mono=True), col("IP", mono=True), col(tr("Asset type"))] + \
           [col(tr(label)) for _, label in CONTROLS]

    def row(a):
        return [cell(a.asset_name, cls="mono"), cell(a.ip_address or "—", cls="mono"),
                cell(a.asset_type.type_name if a.asset_type else "—")] + [state_cell(cov[a.id][k]) for k, _ in CONTROLS]

    if ctx.on("gaps"):
        gaps = [a for a in ctx.assets if any(cov[a.id][k][0] in (OLD, MISSING) for k, _ in CONTROLS)]
        gaps.sort(key=lambda a: (-sum(cov[a.id][k][0] == MISSING for k, _ in CONTROLS), a.asset_name))
        out["gaps"] = [table(tr("Assets with a gap"), head, [row(a) for a in gaps],
                             tr("Every asset is covered."), pdf_limit=200)]

    if ctx.on("by_group"):
        blocks = []
        for title, keyf in ((tr("By asset type"), lambda a: a.asset_type.type_name if a.asset_type else "—"),
                            (tr("By location"), lambda a: (a.location.site_name or a.location.location_name)
                             if getattr(a, "location", None) else tr("No location"))):
            groups = defaultdict(list)
            for a in ctx.assets:
                groups[keyf(a)].append(a)
            rows = []
            for g, members in sorted(groups.items(), key=lambda kv: str(kv[0])):
                r = [cell(g), _num(ctx, len(members))]
                for k, _ in CONTROLS:
                    st = [cov[a.id][k][0] for a in members if cov[a.id][k][0] != NA]
                    r.append(_pct(ctx, 100 * sum(1 for x in st if x == OK) / len(st)) if st else cell("—"))
                rows.append(r)
            blocks.append(table(title, [col(tr("Group")), col(tr("Assets"), num=True)]
                                + [col(tr(label), num=True) for _, label in CONTROLS], rows, "", title=title))
        out["by_group"] = blocks

    if ctx.on("full"):
        out["full"] = [table(tr("Every asset"), head, [row(a) for a in sorted(ctx.assets, key=lambda a: a.asset_name)],
                             tr("No asset in this report."))]
    return out


# ── backup and restore ───────────────────────────────────────────────────

def _backup(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models.backup_restore import BackupRestore
    tr, out, db = ctx.tr, {}, ctx.db
    ids = list(ctx.ids) or [-1]
    network = [a for a in ctx.assets if a.asset_type and (a.asset_type.category or "").lower() == "network"]
    latest = dict(db.query(DeviceBackup.asset_id, func.max(DeviceBackup.created_at))
                  .filter(DeviceBackup.asset_id.in_(ids)).group_by(DeviceBackup.asset_id).all())
    taken = (db.query(DeviceBackup).filter(DeviceBackup.asset_id.in_(ids), DeviceBackup.created_at >= ctx.period.start,
                                           DeviceBackup.created_at < ctx.period.end).all())
    restores = (db.query(BackupRestore).filter(BackupRestore.asset_id.in_(ids),
                                               BackupRestore.created_at >= ctx.period.start,
                                               BackupRestore.created_at < ctx.period.end)
                .order_by(BackupRestore.created_at).all())
    stale = [a for a in network if latest.get(a.id) is None or _ago(ctx, latest[a.id]) > 30]
    users = _owner_names(db, {r.requested_by for r in restores})
    result_text = {"succeeded": (tr("Succeeded"), "up"), "reverted": (tr("Reverted automatically"), "late"),
                   "failed": (tr("Failed"), "late")}

    if ctx.on("overview"):
        done = [r for r in restores if r.status in ("succeeded", "reverted", "failed")]
        out["overview"] = [kpis([
            kpi(tr("Network devices with a recent backup"), tr("{n} of {total}", n=len(network) - len(stale),
                                                                total=len(network)), sub=tr("within 30 days")),
            kpi(tr("Backups taken"), tr.num(len(taken)), sub=tr("in the period")),
            kpi(tr("Restores"), tr.num(len(done)),
                sub=tr("{count} succeeded", count=sum(1 for r in done if r.status == "succeeded"))),
            kpi(tr("Failed or reverted"), tr.num(sum(1 for r in done if r.status != "succeeded"))),
        ]), note(tr("Backup freshness is shown as it is when the report is built; backups and restores are those "
                    "of the period."))]

    if ctx.on("stale"):
        rows = [[cell(a.asset_name, cls="mono"), cell(a.ip_address or "—", cls="mono"),
                 cell(ctx.date(latest[a.id]) if latest.get(a.id) else tr("Never"), cls="late"),
                 cell(tr("{days} days", days=_ago(ctx, latest[a.id])) if latest.get(a.id) else "—",
                      value=_ago(ctx, latest.get(a.id)))]
                for a in sorted(stale, key=lambda a: latest.get(a.id) or datetime.min)]
        out["stale"] = [table(tr("Devices without a recent backup"),
                              [col(tr("Device"), mono=True), col("IP", mono=True), col(tr("Last backup")),
                               col(tr("Age"))], rows, tr("Every network device has a backup from the last 30 days."))]

    if ctx.on("restores"):
        rows = []
        for r in restores:
            text, cls = result_text.get(r.status, (r.status, ""))
            rows.append([cell(_dt(ctx, r.created_at), cls="nowrap"), cell(r.asset_name or "—", cls="mono nowrap"),
                         cell(f"#{r.backup_id}" if r.backup_id else "—", cls="mono"), cell(r.reason or "—"),
                         cell(users.get(r.requested_by, "—")), cell(text, cls=cls),
                         cell((r.error or "")[:200] or "—", cls="small")])
        out["restores"] = [table(tr("Restores"), [col(tr("Time")), col(tr("Device"), mono=True),
                                                  col(tr("From backup"), mono=True), col(tr("Reason")),
                                                  col(tr("Requested by")), col(tr("Result")), col(tr("Detail"))],
                                 rows, tr("No restore in the period."))]

    if ctx.on("taken"):
        per = defaultdict(lambda: defaultdict(int))
        for b in taken:
            per[b.asset_id][b.source or "manual"] += 1
        rows = [[cell(_name(ctx, aid), cls="mono"), _num(ctx, sum(c.values())), _num(ctx, c.get("manual", 0)),
                 _num(ctx, c.get("hardening", 0)), _num(ctx, c.get("pre_restore", 0))]
                for aid, c in sorted(per.items(), key=lambda kv: -sum(kv[1].values()))]
        out["taken"] = [table(tr("Backups taken"), [col(tr("Device"), mono=True), col(tr("Backups"), num=True),
                                                    col(tr("Manual"), num=True), col(tr("Before hardening"), num=True),
                                                    col(tr("Before a restore"), num=True)],
                              rows, tr("No backup was taken in the period."))]

    if ctx.on("system"):
        from app.models.system_backup import SystemBackup, SystemRestore
        sb = (db.query(SystemBackup).filter(SystemBackup.created_at >= ctx.period.start,
                                            SystemBackup.created_at < ctx.period.end,
                                            SystemBackup.kind.in_(("scheduled", "manual")))
              .order_by(SystemBackup.created_at).all())
        tests = (db.query(SystemRestore).filter(SystemRestore.kind == "test",
                                                SystemRestore.created_at >= ctx.period.start,
                                                SystemRestore.created_at < ctx.period.end).all())
        ready = [b for b in sb if b.status == "ready"]
        rows = []
        for b in sb:
            copies = b.destinations or []
            sent = sum(1 for d in copies if d.get("status") == "ok")
            rows.append([cell(_dt(ctx, b.created_at), cls="nowrap"),
                         cell(tr("Scheduled") if b.kind == "scheduled" else tr("Manual")),
                         cell(tr("Ready") if b.status == "ready" else tr("Failed") if b.status == "failed" else b.status,
                              cls="up" if b.status == "ready" else "late"),
                         _num(ctx, round((b.size_bytes or 0) / 1048576, 1), 1),
                         cell(tr("{n} of {total}", n=sent, total=len(copies)) if copies else "—")])
        out["system"] = [kpis([
            kpi(tr("NGCorion backups"), tr.num(len(sb)), sub=tr("{count} ready", count=len(ready))),
            kpi(tr("Restore tests"), tr.num(len(tests)),
                sub=tr("{count} passed", count=sum(1 for t in tests if t.status == "succeeded"))),
        ]), table(tr("NGCorion backups"), [col(tr("Time")), col(tr("Kind")), col(tr("Status")),
                                          col(tr("Size (MB)"), num=True), col(tr("Copies sent"))],
                  rows, tr("No NGCorion backup in the period."))]
    return out


# ── availability (NOC) ───────────────────────────────────────────────────

def _spans(db, asset_ids, start: datetime, end: datetime, now: datetime):
    """{asset: [(start, seconds, up fraction)]} for `reachable`, from the finest
    data still kept: raw samples (a week), 5-minute buckets (30 days), then
    hourly buckets."""
    from app.core.config import settings
    from app.models.noc_metrics import AssetMetricRollup, AssetMetricSample
    interval = settings.NOC_POLL_INTERVAL_SECONDS
    raw_from = max(start, now - timedelta(hours=settings.NOC_METRICS_RAW_RETENTION_HOURS))
    m5_from = max(start, now - timedelta(days=settings.NOC_METRICS_5M_RETENTION_DAYS))
    out = defaultdict(list)
    ids = list(asset_ids) or [-1]
    if raw_from < end:
        for aid, v, at in (db.query(AssetMetricSample.asset_id, AssetMetricSample.value, AssetMetricSample.sampled_at)
                           .filter(AssetMetricSample.asset_id.in_(ids), AssetMetricSample.metric_type == "reachable",
                                   AssetMetricSample.interface_id.is_(None), AssetMetricSample.sampled_at >= raw_from,
                                   AssetMetricSample.sampled_at < end)):
            out[aid].append((at, interval, float(v)))
    for gran, seconds, lo, hi in (("5m", 300, m5_from, raw_from), ("1h", 3600, start, m5_from)):
        if lo >= hi:
            continue
        for aid, avg, n, at in (db.query(AssetMetricRollup.asset_id, AssetMetricRollup.avg_value,
                                         AssetMetricRollup.sample_count, AssetMetricRollup.bucket_start)
                                .filter(AssetMetricRollup.asset_id.in_(ids), AssetMetricRollup.metric_type == "reachable",
                                        AssetMetricRollup.interface_id.is_(None), AssetMetricRollup.granularity == gran,
                                        AssetMetricRollup.bucket_start >= lo, AssetMetricRollup.bucket_start < hi)):
            out[aid].append((at, min(seconds, (n or 1) * interval), float(avg)))
    for aid in out:
        out[aid].sort()
    return out, interval


def _outages(spans, interval) -> List[Tuple[datetime, float]]:
    """(start, seconds down) for each run of samples or buckets that were not all up."""
    found, cur, last_end = [], None, None
    for at, seconds, up in spans:
        gap = last_end is not None and (at - last_end).total_seconds() > 2 * max(interval, seconds)
        if up < 1 and (cur is None or gap):
            if cur:
                found.append(cur)
            cur = [at, (1 - up) * seconds]
        elif up < 1:
            cur[1] += (1 - up) * seconds
        elif cur:
            found.append(cur)
            cur = None
        last_end = at + timedelta(seconds=seconds)
    if cur:
        found.append(cur)
    return [(s, d) for s, d in found if d > 0]


def _noc(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models.noc import AssetSnmpInterface
    tr, out, db = ctx.tr, {}, ctx.db
    target = float(ctx.options.get("target") or 99.9)
    snmp = _monitored_ids(db, list(ctx.ids) or [-1])
    monitored = [a for a in ctx.assets if a.id in snmp]
    end = min(ctx.period.end, ctx.now)
    spans, interval = _spans(db, [a.id for a in monitored], ctx.period.start, end, ctx.now)
    stats = {}
    for a in monitored:
        sp = spans.get(a.id, [])
        total = sum(s for _, s, _ in sp)
        up = sum(s * u for _, s, u in sp)
        outs = _outages(sp, interval)
        stats[a.id] = {"avail": 100 * up / total if total else None, "outages": outs,
                       "down": sum(d for _, d in outs), "measured": total}
    measured = [s for s in stats.values() if s["avail"] is not None]

    def fmt_pct(v):
        if v is None:
            return "—"
        if v >= 99.9995:
            return tr.pct(100)
        return tr.pct(v, 3 if v >= 99.9 else 2)

    if ctx.on("overview"):
        avg = data.average(s["avail"] for s in measured)
        out["overview"] = [kpis([
            kpi(tr("Average availability"), fmt_pct(avg), sub=tr("target {pct}", pct=tr.pct(target, 2 if target % 1 else 0))),
            kpi(tr("Below target"), tr.num(sum(1 for s in measured if s["avail"] < target)),
                sub=tr("of {count} devices measured", count=len(measured))),
            kpi(tr("Outages"), tr.num(sum(len(s["outages"]) for s in stats.values()))),
            kpi(tr("Total downtime"), _duration(ctx, sum(s["down"] for s in stats.values()))),
        ]), note(tr("Measured from the SNMP answer of each device at every poll (about every {seconds} seconds); an "
                    "outage shorter than that may not be seen. Only devices monitored by NOC are included.",
                    seconds=interval))]

    if ctx.on("availability"):
        days = max(1, min(62, (end.date() - ctx.period.start.date()).days + 1))
        rows, chart_rows = [], []
        for a in sorted(monitored, key=lambda a: (stats[a.id]["avail"] if stats[a.id]["avail"] is not None else 101,
                                                  a.asset_name)):
            s = stats[a.id]
            rows.append([cell(a.asset_name, cls="mono"), cell(a.ip_address or "—", cls="mono"),
                         cell(fmt_pct(s["avail"]), value=None if s["avail"] is None else round(s["avail"], 3),
                              cls="late" if s["avail"] is not None and s["avail"] < target else "num"),
                         _num(ctx, len(s["outages"])), cell(_duration(ctx, s["down"]) if s["outages"] else "—")])
            if s["avail"] is None:
                continue
            daily = defaultdict(lambda: [0.0, 0.0])
            for at, sec, up in spans.get(a.id, []):
                d = daily[(at.date() - ctx.period.start.date()).days]
                d[0] += sec
                d[1] += sec * (1 - up)
            segs = []
            for i in range(days):
                tot, down = daily.get(i, (0, 0))
                color = GREY if not tot else GREEN if down == 0 else YELLOW if down < 1800 else RED
                segs.append((100 / days, color))
            chart_rows.append({"label": a.asset_name, "text": fmt_pct(s["avail"]), "segments": segs})
        out["availability"] = [table(tr("Availability by device"),
                                     [col(tr("Device"), mono=True), col("IP", mono=True),
                                      col(tr("Availability"), num=True), col(tr("Outages"), num=True),
                                      col(tr("Downtime"))], rows, tr("No device in this report is monitored by NOC.")),
                               bars(chart_rows[:40], legend=[(tr("No outage"), GREEN), (tr("Outage under 30 min"), YELLOW),
                                                             (tr("Outage of 30 min or more"), RED),
                                                             (tr("Not measured"), GREY)])]

    if ctx.on("outages"):
        rows = []
        for a in monitored:
            for start, seconds in stats[a.id]["outages"]:
                rows.append((start, [cell(a.asset_name, cls="mono"), cell(_dt(ctx, start), cls="nowrap"),
                                     cell(_duration(ctx, seconds), value=round(seconds / 60, 1))]))
        rows.sort(key=lambda x: x[0], reverse=True)
        out["outages"] = [table(tr("Outages"), [col(tr("Device"), mono=True), col(tr("Started")),
                                                col(tr("Duration"))], [r for _, r in rows],
                                tr("No outage in the period."), pdf_limit=150)]

    if ctx.on("interfaces"):
        out["interfaces"] = _busiest_interfaces(ctx, monitored, end)

    if ctx.on("down_ifaces"):
        rows = []
        for i in (db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id.in_([a.id for a in monitored] or [-1]),
                                                       AssetSnmpInterface.if_admin_status == "up",
                                                       AssetSnmpInterface.if_oper_status == "down")):
            rows.append([cell(_name(ctx, i.asset_id), cls="mono"),
                         cell(i.if_name or i.if_descr or str(i.if_index), cls="mono"), cell(i.if_alias or "—"),
                         cell(_dt(ctx, i.last_polled_at))])
        out["down_ifaces"] = [note(tr("Interfaces that are enabled but down at the time the report was built.")),
                              table(tr("Interfaces down"), [col(tr("Device"), mono=True), col(tr("Interface"), mono=True),
                                                            col(tr("Description")), col(tr("Last poll"))], rows,
                                    tr("No enabled interface is down."))]
    return out


def _busiest_interfaces(ctx: Ctx, monitored, end) -> List[dict]:
    """Average and peak use of each interface from its octet counters."""
    from app.models.noc import AssetSnmpInterface
    from app.models.noc_metrics import AssetMetricRollup
    tr, db = ctx.tr, ctx.db
    ifaces = {i.id: i for i in db.query(AssetSnmpInterface).filter(
        AssetSnmpInterface.asset_id.in_([a.id for a in monitored] or [-1]))}
    if not ifaces:
        return [table(tr("Busiest interfaces"), [], [], tr("No interface data in the period."))]
    gran = "5m" if (end - ctx.period.start) <= timedelta(days=30) else "1h"
    seconds = 300 if gran == "5m" else 3600
    usage = defaultdict(lambda: {"bytes": 0.0, "peak": 0.0, "secs": 0.0})
    rows = (db.query(AssetMetricRollup.interface_id, AssetMetricRollup.metric_type, AssetMetricRollup.min_value,
                     AssetMetricRollup.max_value, AssetMetricRollup.bucket_start)
            .filter(AssetMetricRollup.interface_id.in_(list(ifaces)),
                    AssetMetricRollup.metric_type.in_(("if_in_octets", "if_out_octets")),
                    AssetMetricRollup.granularity == gran, AssetMetricRollup.bucket_start >= ctx.period.start,
                    AssetMetricRollup.bucket_start < end)
            .order_by(AssetMetricRollup.interface_id, AssetMetricRollup.metric_type, AssetMetricRollup.bucket_start))
    last = {}
    for iid, metric, lo, hi, at in rows:
        key = (iid, metric)
        delta = max(0.0, (hi or 0) - (lo or 0))
        prev = last.get(key)
        if prev is not None and (hi or 0) >= prev and lo is not None and lo >= prev:
            delta += lo - prev                      # between the last sample of one bucket and the first of the next
        last[key] = hi
        u = usage[key]
        u["bytes"] += delta
        u["secs"] += seconds
        u["peak"] = max(u["peak"], delta * 8 / seconds)
    table_rows = []
    for iid, i in ifaces.items():
        speed = i.if_speed or 0
        if not speed:
            continue
        inn, outt = usage.get((iid, "if_in_octets")), usage.get((iid, "if_out_octets"))
        if not inn and not outt:
            continue
        avg_in = 100 * (inn["bytes"] * 8 / inn["secs"]) / speed if inn and inn["secs"] else 0
        avg_out = 100 * (outt["bytes"] * 8 / outt["secs"]) / speed if outt and outt["secs"] else 0
        peak = 100 * max(inn["peak"] if inn else 0, outt["peak"] if outt else 0) / speed
        table_rows.append((max(avg_in, avg_out), peak, [
            cell(_name(ctx, i.asset_id), cls="mono"), cell(i.if_name or i.if_descr or str(i.if_index), cls="mono"),
            cell(tr("{n} Mb/s", n=round(speed / 1e6)) if speed < 1e9 else tr("{n} Gb/s", n=round(speed / 1e9, 1))),
            _pct(ctx, min(avg_in, 100)), _pct(ctx, min(avg_out, 100)), _pct(ctx, min(peak, 100))]))
    table_rows.sort(key=lambda x: (-x[0], -x[1]))
    return [table(tr("Busiest interfaces"), [col(tr("Device"), mono=True), col(tr("Interface"), mono=True),
                                             col(tr("Speed")), col(tr("Average in"), num=True),
                                             col(tr("Average out"), num=True), col(tr("Peak"), num=True)],
                  [r for _, _, r in table_rows[:25]], tr("No interface data in the period.")),
            note(tr("Peak is the busiest {minutes}-minute interval.", minutes=seconds // 60))]


# ── architecture validation ──────────────────────────────────────────────

def _architecture(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models.architecture_finding import ArchitectureFinding
    from app.models.remediation import ITEM_RESOLVED, RemediationItem
    tr, out, db = ctx.tr, {}, ctx.db
    rows_all = [f for f in db.query(ArchitectureFinding).all() if f.asset_id is None or f.asset_id in ctx.ids]
    open_ = [f for f in rows_all if f.status == "open"]
    decided = [f for f in rows_all if f.status != "open"]
    fixed = (db.query(RemediationItem).filter(RemediationItem.source == "arch", RemediationItem.status == ITEM_RESOLVED,
                                              RemediationItem.resolved_at >= ctx.period.start,
                                              RemediationItem.resolved_at < ctx.period.end).all())
    fixed = [i for i in fixed if i.asset_id is None or i.asset_id in ctx.ids]
    users = _owner_names(db, {f.resolved_by for f in decided})
    sev = lambda f: SEV_ORDER.get((f.severity or "").lower(), 9)  # noqa: E731

    if ctx.on("overview"):
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        for f in open_:
            by_sev[(f.severity or "").lower()] += 1
            by_cat[f.category or "—"] += 1
        total = len(open_) or 1
        out["overview"] = [kpis([
            kpi(tr("Open high-severity findings"), tr.num(by_sev.get("high", 0) + by_sev.get("critical", 0))),
            kpi(tr("Open findings"), tr.num(len(open_))),
            kpi(tr("Decided"), tr.num(len(decided)), sub=tr("accepted or ignored")),
            kpi(tr("Fixed in the period"), tr.num(len(fixed))),
        ]), bars([{"label": tr.severity(s), "text": tr.num(by_sev[s]),
                   "segments": [(100 * by_sev[s] / total, {"high": RED, "medium": YELLOW}.get(s, GREY))]}
                  for s in ("high", "medium", "low") if by_sev.get(s)]
                 + [{"label": tr(str(c).replace("_", " ").capitalize()), "text": tr.num(n),
                     "segments": [(100 * n / total, "#1e3a5f")]} for c, n in sorted(by_cat.items(), key=lambda x: -x[1])],
                 mono_labels=False)]

    if ctx.on("open"):
        rows = [[_sev_cell(ctx, (f.severity or "").lower()), cell(f.rule_code, cls="mono nowrap"), cell(tr(f.title)),
                 cell(f.asset_name or _name(ctx, f.asset_id) if f.asset_id else tr("Whole network"), cls="mono"),
                 cell(tr(f.recommendation) if f.recommendation else "—", cls="small"),
                 cell(ctx.date(f.created_at), cls="nowrap")]
                for f in sorted(open_, key=lambda f: (sev(f), f.rule_code))]
        out["open"] = [table(tr("Open findings"), [col(tr("Severity")), col(tr("Rule"), mono=True), col(tr("Finding")),
                                                   col(tr("Asset"), mono=True), col(tr("Recommendation")),
                                                   col(tr("Found"))], rows, tr("No open finding."), pdf_limit=200)]

    if ctx.on("decisions"):
        rows = [[cell(tr(f.title)), cell(f.rule_code, cls="mono"),
                 cell(f.asset_name or (_name(ctx, f.asset_id) if f.asset_id else tr("Whole network")), cls="mono"),
                 cell(tr("Accepted") if f.status == "accepted" else tr("Ignored")), cell(f.ignored_reason or "—"),
                 cell(users.get(f.resolved_by, "—")), cell(ctx.date(f.resolved_at))]
                for f in sorted(decided, key=lambda f: f.resolved_at or datetime.min, reverse=True)]
        out["decisions"] = [table(tr("Decisions"), [col(tr("Finding")), col(tr("Rule"), mono=True),
                                                    col(tr("Asset"), mono=True), col(tr("Decision")), col(tr("Reason")),
                                                    col(tr("By")), col(tr("Date"))], rows, tr("No decision recorded."))]

    if ctx.on("fixed"):
        rows = [[cell(i.ref, cls="mono"), cell(tr(i.title) if i.title else "—"),
                 cell(_name(ctx, i.asset_id) if i.asset_id else tr("Whole network"), cls="mono"),
                 cell(ctx.date(i.resolved_at))] for i in fixed]
        out["fixed"] = [table(tr("Fixed in the period"), [col(tr("Rule"), mono=True), col(tr("Finding")),
                                                          col(tr("Asset"), mono=True), col(tr("Fixed"))],
                              rows, tr("No finding was fixed in the period."))]
    return out


# ── alerts ───────────────────────────────────────────────────────────────

ALERT_MODULES = (("noc", "NOC"), ("cve", "CVE"), ("audit", "Audit & Hardening"), ("backup", "Backup & Restore"),
                 ("remediation", "Remediation"), ("reports", "Reports"), ("software", "Software"),
                 ("system", "System"))
ALERT_PERMISSION = {"noc": "noc", "cve": "cve", "audit": "auditing", "backup": "backup", "remediation": "remediation",
                    "reports": "reports", "software": "asset_list", "system": "system_config"}


def _alerts(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models.notification import Alert, NotificationRule
    tr, out, db = ctx.tr, {}, ctx.db
    chosen = set(ctx.options.get("modules") or []) or {m for m, _ in ALERT_MODULES}
    allowed = {m for m in chosen if ctx.can(ALERT_PERMISSION.get(m, m))}
    q = db.query(Alert).filter(Alert.module.in_(allowed or {"-"}))
    alerts = [a for a in q.filter(Alert.first_seen_at >= ctx.period.start, Alert.first_seen_at < ctx.period.end)
              if a.asset_id is None or a.asset_id in ctx.ids]
    open_at_end = [a for a in q.filter(Alert.first_seen_at < ctx.period.end)
                   .filter((Alert.resolved_at.is_(None)) | (Alert.resolved_at >= ctx.period.end))
                   if a.asset_id is None or a.asset_id in ctx.ids]
    rules = {r.id: r.name for r in db.query(NotificationRule)}

    def mean_minutes(pairs):
        mins = [(b - a).total_seconds() / 60 for a, b in pairs if a and b and b >= a]
        return sum(mins) / len(mins) if mins else None

    def minutes_text(m):
        return _duration(ctx, m * 60) if m is not None else "—"

    if ctx.on("overview"):
        by_sev = defaultdict(int)
        for a in alerts:
            by_sev[a.severity] += 1
        crit = [a for a in alerts if a.severity == "critical"]
        out["overview"] = [kpis([
            kpi(tr("Alerts"), tr.num(len(alerts)), sub=tr("{count} critical", count=by_sev.get("critical", 0))),
            kpi(tr("Time to acknowledge"), minutes_text(mean_minutes((a.first_seen_at, a.acknowledged_at) for a in crit)),
                sub=tr("average, critical alerts")),
            kpi(tr("Time to resolve"), minutes_text(mean_minutes((a.first_seen_at, a.resolved_at) for a in alerts))),
            kpi(tr("Still open"), tr.num(len(open_at_end)), sub=tr("at the end of the period")),
        ])] + ([note(tr("Some modules are left out because you have no access to them."))]
               if allowed != chosen else [])

    if ctx.on("by_rule"):
        per = defaultdict(list)
        for a in alerts:
            per[rules.get(a.rule_id) or a.event_type].append(a)
        rows = [[cell(tr(name)), _num(ctx, len(xs)), _num(ctx, sum(1 for a in xs if a.severity == "critical")),
                 cell(minutes_text(mean_minutes((a.first_seen_at, a.acknowledged_at) for a in xs))),
                 cell(minutes_text(mean_minutes((a.first_seen_at, a.resolved_at) for a in xs)))]
                for name, xs in sorted(per.items(), key=lambda kv: -len(kv[1]))]
        out["by_rule"] = [table(tr("By rule"), [col(tr("Rule")), col(tr("Alerts"), num=True),
                                                col(tr("Critical"), num=True), col(tr("Time to acknowledge")),
                                                col(tr("Time to resolve"))], rows, tr("No alert in the period."))]

    if ctx.on("sources"):
        per = defaultdict(list)
        for a in alerts:
            per[(a.source_label or "—", rules.get(a.rule_id) or a.event_type)].append(a)
        total = len(alerts) or 1
        top = sorted(per.items(), key=lambda kv: -len(kv[1]))[:15]
        out["sources"] = [table(tr("Noisiest sources"), [col(tr("Source"), mono=True), col(tr("Rule")),
                                                         col(tr("Alerts"), num=True), col(tr("Share"), num=True)],
                                [[cell(src), cell(tr(rule)), _num(ctx, len(xs)), _pct(ctx, 100 * len(xs) / total)]
                                 for (src, rule), xs in top], tr("No alert in the period."))]

    status_text = {"active": tr("Active"), "acknowledged": tr("Acknowledged"), "resolved": tr("Resolved")}
    if ctx.on("open"):
        rows = [[_sev_cell(ctx, a.severity), cell(tr(a.title)), cell(a.source_label or "—"),
                 cell(_dt(ctx, a.first_seen_at), cls="nowrap"), cell(status_text.get(a.status, a.status))]
                for a in sorted(open_at_end, key=lambda a: (SEV_ORDER.get(a.severity, 9), a.first_seen_at))]
        out["open"] = [table(tr("Still open"), [col(tr("Severity")), col(tr("Alert")), col(tr("Source")),
                                                col(tr("Since")), col(tr("Status"))], rows,
                             tr("No alert was open at the end of the period."))]

    if ctx.on("all"):
        rows = [[_sev_cell(ctx, a.severity), cell(tr(a.title)), cell(tr(a.detail) if a.detail else "—"),
                 cell(a.source_label or "—"), cell(_dt(ctx, a.first_seen_at)),
                 cell(_dt(ctx, a.acknowledged_at) if a.acknowledged_at else "—"),
                 cell(_dt(ctx, a.resolved_at) if a.resolved_at else "—"), cell(status_text.get(a.status, a.status))]
                for a in sorted(alerts, key=lambda a: a.first_seen_at)]
        out["all"] = [table(tr("Every alert"), [col(tr("Severity")), col(tr("Alert")), col(tr("Detail")),
                                                col(tr("Source")), col(tr("Raised")), col(tr("Acknowledged")),
                                                col(tr("Resolved")), col(tr("Status"))], rows,
                            tr("No alert in the period."))]
    return out


# ── user activity ────────────────────────────────────────────────────────

_SENSITIVE = re.compile(r"delete|restore|reset|permission|role|password|harden|execute_single|batch_execute|"
                        r"settings|license|licence|passphrase|rekey|disable|unmap|revoke|approve", re.I)
# Everything done in these modules changes who can do what or how NGCorion runs.
_SENSITIVE_MODULES = {"user_management", "system_config", "license"}


def _sensitive(a) -> bool:
    action = a.action or ""
    if action in ("execute_audit", "audit_executed", "auth.login"):
        return False
    return (a.module or "") in _SENSITIVE_MODULES or bool(_SENSITIVE.search(action))


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _users(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models import User
    from app.models.login_log import LoginLog
    from app.models.security_audit_log import AuditLog
    tr, out, db = ctx.tr, {}, ctx.db
    start, end = _aware(ctx.period.start), _aware(ctx.period.end)
    logins = db.query(LoginLog).filter(LoginLog.timestamp >= start, LoginLog.timestamp < end).all()
    actions = [a for a in db.query(AuditLog).filter(AuditLog.timestamp >= start, AuditLog.timestamp < end)
               .order_by(AuditLog.timestamp) if _sensitive(a)]
    users = db.query(User).all()
    last_ok = dict(db.query(LoginLog.username, func.max(LoginLog.timestamp)).filter(LoginLog.success.is_(True))
                   .group_by(LoginLog.username).all())
    cutoff = _aware(ctx.now) - timedelta(days=90)
    inactive = [u for u in users if u.is_active and (last_ok.get(u.username) is None
                                                     or _aware(last_ok[u.username]) < cutoff)]
    failed = [g for g in logins if not g.success]

    def local(dt):
        return ctx.short(dt.astimezone(timezone.utc).replace(tzinfo=None) if dt and dt.tzinfo else dt)

    if ctx.on("overview"):
        by_ip = defaultdict(int)
        for g in failed:
            by_ip[g.ip_address or "—"] += 1
        worst = max(by_ip.values()) if by_ip else 0
        out["overview"] = [kpis([
            kpi(tr("Successful logins"), tr.num(sum(1 for g in logins if g.success))),
            kpi(tr("Failed logins"), tr.num(len(failed)),
                sub=tr("{count} from one address", count=worst) if worst > 1 else ""),
            kpi(tr("Sensitive actions"), tr.num(len(actions))),
            kpi(tr("Unused accounts"), tr.num(len(inactive)), sub=tr("no login in 90 days")),
        ])]

    if ctx.on("users"):
        role = lambda u: tr({"admin": "System administrator", "manager": "Manager", "user": "User", "guest": "Guest"}  # noqa
                            .get(u.role.value if hasattr(u.role, "value") else str(u.role), str(u.role)))
        per_ok, per_fail, per_act = defaultdict(int), defaultdict(int), defaultdict(int)
        for g in logins:
            (per_ok if g.success else per_fail)[g.username] += 1
        for a in actions:
            per_act[a.username] += 1
        rows = [[cell(u.username, cls="mono"), cell(role(u)), cell(tr("Active") if u.is_active else tr("Disabled")),
                 _num(ctx, per_ok.get(u.username, 0)), _num(ctx, per_fail.get(u.username, 0)),
                 cell(local(last_ok.get(u.username)) if last_ok.get(u.username) else tr("Never")),
                 _num(ctx, per_act.get(u.username, 0))]
                for u in sorted(users, key=lambda u: (-per_act.get(u.username, 0), u.username))]
        out["users"] = [table(tr("Users"), [col(tr("User"), mono=True), col(tr("Role")), col(tr("Account")),
                                            col(tr("Logins"), num=True), col(tr("Failed logins"), num=True),
                                            col(tr("Last login")), col(tr("Sensitive actions"), num=True)],
                              rows, tr("No user."))]

    if ctx.on("failed_by_ip"):
        per = defaultdict(list)
        for g in failed:
            per[g.ip_address or "—"].append(g)
        rows = [[cell(ip, cls="mono"), _num(ctx, len(gs)),
                 cell(", ".join(sorted({g.username for g in gs}))[:200], cls="mono"),
                 cell(f"{local(min(g.timestamp for g in gs))} – {local(max(g.timestamp for g in gs))}")]
                for ip, gs in sorted(per.items(), key=lambda kv: -len(kv[1]))]
        out["failed_by_ip"] = [table(tr("Failed logins by address"), [col("IP", mono=True), col(tr("Attempts"), num=True),
                                                                      col(tr("Usernames tried"), mono=True),
                                                                      col(tr("When"))], rows,
                                     tr("No failed login in the period."))]

    if ctx.on("sensitive"):
        rows = [[cell(_dt(ctx, a.timestamp), cls="nowrap"), cell(a.username or "—", cls="mono"),
                 cell(a.action, cls="mono"),
                 cell(a.module or "—"), cell(tr("Succeeded") if a.result == "success" else tr("Failed"),
                                            cls="" if a.result == "success" else "late"),
                 cell((a.detail or "—")[:300], cls="small")] for a in reversed(actions)]
        out["sensitive"] = [table(tr("Sensitive actions"), [col(tr("Time")), col(tr("User"), mono=True),
                                                            col(tr("Action"), mono=True), col(tr("Module")),
                                                            col(tr("Result")), col(tr("Detail"))], rows,
                                  tr("No sensitive action in the period."), pdf_limit=250)]

    if ctx.on("inactive"):
        rows = [[cell(u.username, cls="mono"), cell(local(last_ok.get(u.username)) if last_ok.get(u.username)
                                                    else tr("Never")), cell(ctx.date(u.created_at))]
                for u in sorted(inactive, key=lambda u: u.username)]
        out["inactive"] = [note(tr("Active accounts with no successful login in the last 90 days; disable the ones "
                                   "nobody uses.")),
                           table(tr("Unused accounts"), [col(tr("User"), mono=True), col(tr("Last login")),
                                                         col(tr("Created"))], rows, tr("Every account is in use."))]
    return out


# ── software inventory ───────────────────────────────────────────────────

SW_SOURCE = {"distro": "Distribution repository", "third_party": "Third-party repository",
             "manual": "Installed manually", "windows": "Windows program", "service": "Read by the product's audit",
             "firmware": "Device firmware"}


def _software(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models.software import SoftwareChange, SoftwareItem
    from app.modules.software import service as sw
    tr, out, db = ctx.tr, {}, ctx.db
    data_ = ctx.cached("software", lambda: sw.products(db, list(ctx.ids)))
    items = data_["items"]
    s = data_["summary"]
    outside = [r for r in items if any(x != "distro" for x in r["sources"])]
    vulnerable = [r for r in items if r["cve"]]
    changes = (db.query(SoftwareChange).filter(SoftwareChange.asset_id.in_(list(ctx.ids) or [-1]),
                                               SoftwareChange.change == "added",
                                               SoftwareChange.at >= ctx.period.start, SoftwareChange.at < ctx.period.end,
                                               SoftwareChange.source != "distro")
               .order_by(SoftwareChange.at.desc()).all())

    def sources(r):
        return ", ".join(tr(SW_SOURCE.get(x, x)) for x in r["sources"])

    def versions(r, limit=4):
        return ", ".join(f"{v['version'] or '?'} ×{v['assets']}" for v in r["versions"][:limit])

    if ctx.on("overview"):
        manual = sum(1 for c in changes if c.source == "manual")
        out["overview"] = [kpis([
            kpi(tr("Assets with a software list"), tr("{n} of {total}", n=s["assets_with_inventory"],
                                                      total=s["assets_total"])),
            kpi(tr("Products outside the distribution repository"), tr.num(len(outside)),
                sub=tr("{count} installed packages in total", count=s["packages"])),
            kpi(tr("Products with known vulnerabilities"), tr.num(len(vulnerable)),
                sub=tr("{count} exploited", count=sum(1 for r in vulnerable if r["cve"]["kev"]))),
            kpi(tr("New software in the period"), tr.num(len(changes)), sub=tr("{count} installed manually", count=manual)),
        ]), note(tr("Packages from the distribution's own repository are matched against the distribution's own "
                    "security advisories (Ubuntu USN, Debian DSA/DLA, Red Hat RHSA, Rocky RLSA, AlmaLinux ALSA), "
                    "the rest against NVD."))]

    if ctx.on("vulnerable"):
        rows = [[cell(r["label"]), cell(" ".join(r["cpes"]), cls="mono"), _num(ctx, r["asset_count"]),
                 cell(", ".join(r["cve"]["affected_versions"]) or "—", cls="mono"),
                 _num(ctx, r["cve"]["count"]), _sev_cell(ctx, r["cve"]["severity"], r["cve"]["kev"]),
                 cell(", ".join(r["cve"]["fixed_in"]) or tr("see the advisory"), cls="mono")]
                for r in vulnerable]
        out["vulnerable"] = [table(tr("Vulnerable products"), [col(tr("Product")), col("CPE", mono=True),
                                                               col(tr("Assets"), num=True),
                                                               col(tr("Affected versions"), mono=True),
                                                               col(tr("CVEs"), num=True), col(tr("Highest severity")),
                                                               col(tr("Fixed in"), mono=True)], rows,
                                   tr("No product with a known vulnerability."))]

    if ctx.on("new"):
        known_origins = defaultdict(set)
        for aid, origin, first in db.query(SoftwareItem.asset_id, SoftwareItem.origin, SoftwareItem.first_seen).filter(
                SoftwareItem.asset_id.in_(list(ctx.ids) or [-1]), SoftwareItem.origin.isnot(None)):
            known_origins[aid].add((origin, first))
        rows = []
        for c in changes:
            new_repo = c.source == "third_party" and c.origin and not any(
                o == c.origin and first < c.at - timedelta(minutes=1) for o, first in known_origins[c.asset_id])
            label = tr(SW_SOURCE.get(c.source, c.source)) + (f" · {c.origin}" if c.origin else "")
            rows.append([cell(_name(ctx, c.asset_id), cls="mono"), cell(c.name, cls="mono"),
                         cell(c.new_version or "—", cls="mono"),
                         cell(label + (" · " + tr("new repository") if new_repo else ""),
                              cls="late" if c.source == "manual" or new_repo else ""),
                         cell(ctx.date(c.at), cls="nowrap")])
        out["new"] = [table(tr("New software in the period"), [col(tr("Asset"), mono=True), col(tr("Software"), mono=True),
                                                               col(tr("Version"), mono=True), col(tr("Source")),
                                                               col(tr("Date"))], rows,
                            tr("No software was installed from outside the distribution in the period."),
                            pdf_limit=200)]

    if ctx.on("outside"):
        rows = [[cell(r["label"]), cell(sources(r)), cell(", ".join(r["origins"]) or "—", cls="mono"),
                 cell(versions(r), cls="mono"), _num(ctx, r["asset_count"]),
                 cell(r["cve"] and tr("{count} CVEs", count=r["cve"]["count"]) or "—")]
                for r in sorted(outside, key=lambda r: (-(r["cve"] or {}).get("count", 0), r["label"].lower()))]
        out["outside"] = [table(tr("Outside the distribution repository"),
                                [col(tr("Product")), col(tr("Source")), col(tr("Repository"), mono=True),
                                 col(tr("Versions in use"), mono=True), col(tr("Assets"), num=True),
                                 col(tr("Vulnerabilities"))], rows, tr("Everything comes from the distribution."),
                                pdf_limit=200)]

    if ctx.on("versions"):
        rows = [[cell(r["label"]), _num(ctx, len(r["versions"])), cell(versions(r, 8), cls="mono"),
                 _num(ctx, r["asset_count"])] for r in items if len(r["versions"]) > 1 and r["status"] != "distro"]
        out["versions"] = [table(tr("Several versions"), [col(tr("Product")), col(tr("Versions"), num=True),
                                                          col(tr("Versions in use"), mono=True),
                                                          col(tr("Assets"), num=True)], rows,
                                 tr("Every product runs a single version."))]

    if ctx.on("unidentified"):
        rows = [[cell(r["label"], cls="mono"), cell(sources(r)), cell(versions(r), cls="mono"),
                 _num(ctx, r["asset_count"])] for r in items if r["status"] == "unknown"]
        out["unidentified"] = [note(tr("Software the built-in catalog does not know. Name its CPE on the Software page "
                                       "so it is matched against NVD, or mark it as internal.")),
                               table(tr("Unidentified"), [col(tr("Software"), mono=True), col(tr("Source")),
                                                          col(tr("Versions in use"), mono=True),
                                                          col(tr("Assets"), num=True)], rows,
                                     tr("Every product is identified."))]

    if ctx.on("full"):
        rows = [[cell(_name(ctx, i.asset_id), cls="mono"), cell(i.name, cls="mono"), cell(i.version or "—", cls="mono"),
                 cell(i.arch or "—", cls="mono"), cell(tr(SW_SOURCE.get(i.source, i.source))), cell(i.origin or "—")]
                for i in db.query(SoftwareItem).filter(SoftwareItem.asset_id.in_(list(ctx.ids) or [-1]))
                .order_by(SoftwareItem.asset_id, SoftwareItem.name)]
        out["full"] = [table(tr("Every installed package"), [col(tr("Asset"), mono=True), col(tr("Name"), mono=True),
                                                             col(tr("Version"), mono=True), col(tr("Architecture"), mono=True),
                                                             col(tr("Source")), col(tr("Repository"))], rows,
                             tr("No software list for these assets."))]
    return out


# ── the templates ────────────────────────────────────────────────────────

PHASE2 = (
    Template("audit_session", "Audit details",
             "The full result of one audit with the evidence of every check; for the auditor.",
             "audit", "auditing", sections=[
                 Section("summary", "Summary", "auditing"),
                 Section("failed", "Failed checks", "auditing", "With evidence and how to fix"),
                 Section("errors", "Errors and not applicable", "auditing", "Checks that need a look by hand"),
                 Section("passed", "Passed checks", "auditing"),
                 Section("compare", "Change since the previous audit", "auditing", "Newly failing, newly passing",
                         default=False),
             ], options=[Option("audit_mode", "Which audit", "choice", "latest", AUDIT_MODES),
                         Option("audit_session", "Audit", "int", None),
                         Option("guidance", "Include why each check matters and how to fix it", "bool", True)],
             default_period="last_30_days", build=_audit, uses_period=False),
    Template("hardening_changes", "Hardening changes",
             "What changed, on which device, by whom, with the backup taken before the change.",
             "audit", "hardening", sections=[
                 Section("overview", "Overview", "hardening"),
                 Section("by_asset", "By asset", "hardening"),
                 Section("changes", "Every change", "hardening", "Time, asset, check, user, result"),
                 Section("failed", "Failed changes", "hardening", "With the error"),
             ], options=[Option("commands", "Include the commands sent to the device", "bool", True)],
             build=_hardening),
    Template("asset_coverage", "Assets and coverage",
             "Which assets are audited, backed up, monitored and have a software list, and which are not.",
             "infrastructure", "asset_list", sections=[
                 Section("overview", "Coverage", "asset_list"),
                 Section("gaps", "Assets with a gap", "asset_list", "Only the assets that miss something"),
                 Section("by_group", "By asset type and location", "asset_list"),
                 Section("full", "Every asset", "asset_list", "As a separate Excel file", default=False,
                         excel_only=True),
             ], options=[Option("audit_days", "An audit counts as recent within", "choice", "90",
                                (("30", "30 days"), ("90", "90 days"), ("180", "180 days")))],
             default_period="last_30_days", build=_coverage, uses_period=False),
    Template("backup", "Backup and restore", "How recent each device's backup is, restores and their result.",
             "infrastructure", "backup", sections=[
                 Section("overview", "Overview", "backup"),
                 Section("stale", "Devices without a recent backup", "backup"),
                 Section("restores", "Restores", "backup", "Who, why, result, automatic revert"),
                 Section("taken", "Backups taken", "backup", "By device and source", default=False),
                 Section("system", "NGCorion's own backups", "system_config", "Administrators only", default=False),
             ], build=_backup),
    Template("noc", "Availability (NOC)", "Availability, outages and interface use.", "infrastructure", "noc",
             sections=[
                 Section("overview", "Overview", "noc"),
                 Section("availability", "Availability by device", "noc", "With a bar for every day"),
                 Section("outages", "Outages", "noc", "Start and duration"),
                 Section("interfaces", "Busiest interfaces", "noc", "Average and peak"),
                 Section("down_ifaces", "Interfaces down", "noc", "Enabled but down now", default=False),
             ], options=[Option("target", "Availability target", "choice", "99.9",
                                (("99", "99%"), ("99.5", "99.5%"), ("99.9", "99.9%"), ("99.99", "99.99%")))],
             default_period="last_30_days", build=_noc),
    Template("architecture", "Architecture validation", "Architecture findings and the decision on each.",
             "infrastructure", "architecture_validation", sections=[
                 Section("overview", "Overview", "architecture_validation"),
                 Section("open", "Open findings", "architecture_validation", "With the recommendation"),
                 Section("decisions", "Decisions", "architecture_validation", "Accepted or ignored, with the reason"),
                 Section("fixed", "Fixed in the period", "architecture_validation", default=False),
             ], build=_architecture),
    Template("alerts", "Alerts", "Alerts in the period, time to acknowledge and resolve, noisiest sources.",
             "system", None, sections=[
                 Section("overview", "Overview", None),
                 Section("by_rule", "By rule", None),
                 Section("sources", "Noisiest sources", None),
                 Section("open", "Still open", None, "At the end of the period"),
                 Section("all", "Every alert", None, "As a separate Excel file", default=False, excel_only=True),
             ], options=[Option("modules", "Modules", "multi", [], ALERT_MODULES)],
             default_period="last_30_days", build=_alerts),
    Template("user_activity", "User activity", "Logins, failed logins and sensitive actions of each user.",
             "system", "logs", sections=[
                 Section("overview", "Overview", "logs"),
                 Section("users", "Each user", "logs", "Logins, last login, sensitive actions"),
                 Section("failed_by_ip", "Failed logins by address", "logs"),
                 Section("sensitive", "Sensitive actions", "logs", "Hardening, restores, deletions, permissions, "
                                                                    "settings"),
                 Section("inactive", "Unused accounts", "logs", "No login in 90 days"),
             ], default_period="last_30_days", build=_users, admin_only=True, uses_assets=False),
    Template("software", "Software inventory",
             "Software outside the distribution repository, vulnerable products and new installations.",
             "vulnerability", "asset_list", sections=[
                 Section("overview", "Overview", "asset_list"),
                 Section("vulnerable", "Vulnerable products", "asset_list", "Affected versions and the fix"),
                 Section("new", "New software in the period", "asset_list", "Installed manually or from a new "
                                                                             "repository"),
                 Section("outside", "Outside the distribution repository", "asset_list"),
                 Section("versions", "Several versions", "asset_list", "Products with more than one version",
                         default=False),
                 Section("unidentified", "Unidentified", "asset_list", default=False),
                 Section("full", "Every installed package", "asset_list", "As a separate Excel file", default=False,
                         excel_only=True),
             ], default_period="last_30_days", build=_software),
)
