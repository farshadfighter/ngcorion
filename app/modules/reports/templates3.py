"""
Report templates, third set: end of life (app/modules/eol), and compliance with a standard (app/modules/compliance) — the standard's score,
each requirement with its status and evidence, the failing checks behind the gaps, the requirements
assessed by hand or still to assess, and (in Excel) every failed check of every asset.

The figures are those of the Compliance page for the same standard and asset group, limited to the
report's asset filter; they describe the latest audits when the report is built, not a period.
"""
from collections import defaultdict
from typing import Dict, List

from app.modules.reports.templates import (Ctx, Option, Section, Template, _pct, _sev_cell, bars, cell, col, kpi,
                                           kpis, note, table)

GREEN, YELLOW, RED, GREY = "#2f9e5b", "#d9a514", "#c0262d", "#cfd6e1"
STATUS = {"met": "Met", "partial": "Partly met", "not_met": "Not met", "not_applicable": "Not applicable",
          "not_assessed": "Not assessed"}
STATUS_CLS = {"met": "up", "partial": "", "not_met": "down"}


def _standards(db) -> List[tuple]:
    from app.models.compliance import ComplianceStandard
    from app.modules.compliance import service
    service.sync_builtin(db)
    rows = db.query(ComplianceStandard).filter(ComplianceStandard.enabled.is_(True)) \
        .order_by(ComplianceStandard.builtin.desc(), ComplianceStandard.name).all()
    return [(s.key, f"{s.name} {s.version}".strip() if s.version else s.name) for s in rows]


def _groups(db) -> List[tuple]:
    from app.models.asset_groups import AssetGroup
    return [("all", "Every asset")] + [(str(g.id), g.name) for g in db.query(AssetGroup).order_by(AssetGroup.name)]


def _status_cell(ctx: Ctx, status: str) -> dict:
    return cell(ctx.tr(STATUS[status]), value=ctx.tr(STATUS[status]), cls=STATUS_CLS.get(status, ""))


def _title(ctx: Ctx, obj) -> str:
    fa = getattr(obj, "title_fa", None) if not isinstance(obj, dict) else obj.get("title_fa")
    en = getattr(obj, "title", None) if not isinstance(obj, dict) else obj.get("title")
    return fa if ctx.lang == "fa" and fa else en


def _compliance(ctx: Ctx) -> Dict[str, List[dict]]:
    from app.models.compliance import ComplianceSection, ComplianceStandard
    from app.modules.compliance import service
    tr, db, out = ctx.tr, ctx.db, {}
    service.sync_builtin(db)
    key = ctx.options.get("standard") or "pci-dss-4.0"
    std = db.query(ComplianceStandard).filter(ComplianceStandard.key == key).first()
    if std is None:
        return {s: [note(tr("The standard of this report no longer exists."))] for s in ctx.sections}
    group_raw = ctx.options.get("group") or "all"
    group_id = int(group_raw) if group_raw.isdigit() else None
    stats = service.check_stats(db, group_id, ctx.ids)
    scored, summary = service.evaluate(db, std, stats, group_id, ctx.now.replace(tzinfo=None))
    std_name = f"{std.name} {std.version}".strip() if std.version else std.name
    ctx.header_line = tr("{standard}, latest audits as of {date}", standard=std_name, date=ctx.date(ctx.now))
    if group_id is not None:
        from app.models.asset_groups import AssetGroup
        g = db.get(AssetGroup, group_id)
        ctx.scope_line = tr("Asset group {name}", name=g.name) if g else None
    counts = summary["counts"]

    if ctx.on("overview"):
        blocks = [kpis([
            kpi(tr("Compliance"), tr.pct(summary["score"]) if summary["score"] is not None else "—",
                sub=tr("mean of the scored requirements")),
            kpi(tr("Met"), tr.num(counts.get("met", 0)), sub=tr("of {n} requirements", n=tr.num(summary["requirements"]))),
            kpi(tr("Partly or not met"), tr.num(counts.get("partial", 0) + counts.get("not_met", 0))),
            kpi(tr("Not assessed"), tr.num(counts.get("not_assessed", 0)),
                sub=tr("coverage {pct}", pct=tr.pct(summary["coverage"]))),
        ])]
        sections = db.query(ComplianceSection).filter(ComplianceSection.standard_id == std.id) \
            .order_by(ComplianceSection.position).all()
        by_section = defaultdict(list)
        for r, res in scored:
            if res["score"] is not None:
                by_section[r.section].append(res["score"])
        rows = []
        for s in sections:
            vals = by_section.get(s.ref)
            if not vals:
                continue
            avg = sum(vals) / len(vals)
            rows.append({"label": f"{s.ref} {_title(ctx, s)}", "text": tr.pct(avg),
                         "segments": [(avg, GREEN if avg >= 90 else YELLOW if avg >= 60 else RED)]})
        if rows:
            blocks.append(bars(rows, mono_labels=False))
        blocks.append(note(tr("Requirements are evidenced by the audit checks of their security domains; a "
                              "requirement no check covers is assessed by hand. The score is indicative and does "
                              "not replace an assessment by an auditor of the standard.")))
        out["overview"] = blocks

    if ctx.on("requirements"):
        rows = [[cell(r.ref, cls="mono nowrap"), cell(_title(ctx, r)), _status_cell(ctx, res["status"]),
                 _pct(ctx, res["score"]),
                 cell(tr("{passed} passed, {failed} failed", passed=tr.num(res["passed"]),
                         failed=tr.num(res["failed"])) if res["passed"] + res["failed"] else "—", cls="small"),
                 cell(tr("Audits") if res["source"] == "audit" else tr("By hand") if res["source"] == "manual"
                      else "—")]
                for r, res in scored]
        out["requirements"] = [table(tr("Requirements"), [col(tr("Ref."), mono=True), col(tr("Requirement")),
                                                          col(tr("Status")), col(tr("Score"), num=True),
                                                          col(tr("Results")), col(tr("Evidence"))],
                                     rows, tr("The standard has no requirement."))]

    if ctx.on("gaps"):
        reqs = [r for r, _ in scored]
        gaps = service.gaps(reqs, stats)
        rows = [[_sev_cell(ctx, g["severity"]), cell(g["check_number"], cls="mono nowrap"), cell(g["benchmark"],
                                                                                              cls="mono"),
                 cell(g["title"]), cell(tr.num(g["failing_assets"]), value=g["failing_assets"], cls="num"),
                 cell("، ".join(g["requirements"]) if ctx.lang == "fa" else ", ".join(g["requirements"]),
                      cls="mono small")]
                for g in gaps]
        out["gaps"] = [table(tr("Gaps"), [col(tr("Severity")), col(tr("Check"), mono=True), col(tr("Benchmark"), mono=True),
                                          col(tr("Title")), col(tr("Assets failing"), num=True),
                                          col(tr("Requirements"), mono=True)],
                             rows, tr("No failing check holds this standard back."), pdf_limit=150)]

    if ctx.on("manual"):
        assessed = service.assessments_for(db, std.id, group_id)
        from app.modules.compliance.router import _usernames
        users = _usernames(db, [a.assessed_by for a in assessed.values()])
        rows = []
        for r, res in scored:
            a = assessed.get(r.id)
            if res["source"] == "audit" and not a:
                continue
            if a is None and res["status"] != "not_assessed":
                continue
            rows.append([cell(r.ref, cls="mono nowrap"), cell(_title(ctx, r)), _status_cell(ctx, res["status"]),
                         cell(a.note if a else tr("Not assessed yet"), cls="small"),
                         cell(users.get(a.assessed_by, "—") if a else "—"),
                         cell(ctx.date(a.valid_until) if a and a.valid_until else "—", cls="nowrap")])
        out["manual"] = [table(tr("Assessed by hand"), [col(tr("Ref."), mono=True), col(tr("Requirement")),
                                                        col(tr("Status")), col(tr("Note")), col(tr("By")),
                                                        col(tr("Valid until"))],
                               rows, tr("Every requirement is evidenced by the audits."))]

    if ctx.on("failed_all"):
        relevant = {g["check_number"] + "|" + g["benchmark"] for g in service.gaps([r for r, _ in scored], stats)}
        names = {a.id: a.asset_name for a in ctx.assets}
        rows = [[cell(names.get(a, f"#{a}"), cls="mono"), cell(b, cls="mono"), cell(n, cls="mono"), cell(t),
                 _sev_cell(ctx, sev)]
                for a, b, n, t, sev in sorted(service.failing_results(db, group_id, ctx.ids),
                                              key=lambda x: (names.get(x[0], ""), x[1], x[2]))
                if f"{n}|{b}" in relevant]
        out["failed_all"] = [table(tr("Failed checks"), [col(tr("Asset"), mono=True), col(tr("Benchmark"), mono=True),
                                                         col(tr("Check"), mono=True), col(tr("Title")),
                                                         col(tr("Severity"))], rows, tr("No failed check."))]
    return out


EOL_STATUS = {"unsupported": "Unsupported", "extended": "Paid extended support only", "ending": "Ending soon",
              "supported": "Supported", "unknown": "Not in the catalog"}
EOL_CLS = {"unsupported": "down", "extended": "", "ending": "", "supported": "up"}


def _end_of_life(ctx: Ctx) -> Dict[str, List[dict]]:
    """Operating systems, firmware and server software of the report's assets against their vendor's
    support (app/modules/eol), as when the report is built."""
    from app.modules.eol import service as eol
    tr, db, out = ctx.tr, ctx.db, {}
    comps = eol.components(db, ctx.ids, today=ctx.now.date())
    names = {a.id: a.asset_name for a in ctx.assets}
    per_asset = eol.by_asset(comps)
    ctx.header_line = tr("Vendor support as of {date}", date=ctx.date(ctx.now))

    def rows(statuses, date_col):
        sel = sorted((c for c in comps if c.status in statuses), key=lambda c: (c.until or "9999", c.title))
        return [[cell(names.get(c.asset_id, f"#{c.asset_id}"), cls="mono"), cell(c.title),
                 cell(c.version or "—", cls="mono"), cell(_iso_date(ctx, getattr(c, date_col)), cls="nowrap"),
                 cell(tr(EOL_STATUS[c.status]), cls=EOL_CLS.get(c.status, ""))] for c in sel]

    cols = lambda when: [col(tr("Asset"), mono=True), col(tr("Software")), col(tr("Version"), mono=True),  # noqa: E731
                         col(when), col(tr("Status"))]
    if ctx.on("overview"):
        worst = defaultdict(int)
        for cs in per_asset.values():
            worst[eol.worst(cs)] += 1
        total = len(per_asset) or 1
        out["overview"] = [kpis([
            kpi(tr("Assets with unsupported software"), tr.num(worst.get("unsupported", 0)),
                sub=tr("of {n} assets with known software", n=tr.num(len(per_asset)))),
            kpi(tr("Only paid extended support"), tr.num(worst.get("extended", 0))),
            kpi(tr("Support ends soon"), tr.num(worst.get("ending", 0)),
                sub=tr("within {days} days", days=tr.num(eol.get_settings(db)["warn_days"]))),
            kpi(tr("Supported"), tr.num(worst.get("supported", 0))),
        ]), bars([{"label": tr(EOL_STATUS[k]), "text": tr.num(worst.get(k, 0)),
                   "segments": [(100 * worst.get(k, 0) / total, c)]}
                  for k, c in (("unsupported", RED), ("extended", YELLOW), ("ending", YELLOW), ("supported", GREEN))
                  if worst.get(k)], mono_labels=False),
            note(tr("Release cycles and dates from endoflife.date as kept in this installation; software the "
                    "catalog does not know is listed separately."))]
    if ctx.on("unsupported"):
        out["unsupported"] = [table(tr("Unsupported"), cols(tr("Support ended")), rows(("unsupported",), "until"),
                                    tr("No software past the end of support."))]
    if ctx.on("extended"):
        out["extended"] = [table(tr("Paid extended support only"), cols(tr("Extended support until")),
                                 rows(("extended",), "until"), tr("Nothing relies on paid extended support."))]
    if ctx.on("ending"):
        out["ending"] = [table(tr("Ending soon"), cols(tr("Support ends")), rows(("ending",), "until"),
                               tr("No support ends soon."))]
    if ctx.on("unknown"):
        unknown = defaultdict(set)
        for c in comps:
            if c.status == "unknown":
                unknown[(c.name, c.version or "—")].add(c.asset_id)
        out["unknown"] = [table(tr("Not in the catalog"), [col(tr("Software")), col(tr("Version"), mono=True),
                                                           col(tr("Assets"), num=True)],
                                [[cell(n), cell(v, cls="mono"), cell(tr.num(len(ids)), value=len(ids), cls="num")]
                                 for (n, v), ids in sorted(unknown.items(), key=lambda x: -len(x[1]))],
                                tr("All software found is in the catalog."))]
    if ctx.on("all"):
        out["all"] = [table(tr("All software"), cols(tr("Support until")),
                            rows(("unsupported", "extended", "ending", "supported"), "until"), tr("No software found."))]
    return out


def _iso_date(ctx: Ctx, value) -> str:
    from datetime import date as _d
    if not value:
        return "—"
    try:
        return ctx.date(_d.fromisoformat(value[:10]))
    except ValueError:
        return value


PHASE3 = (
    Template("compliance_standard", "Compliance with a standard",
             "Score of a standard (PCI DSS, ISO/IEC 27001, NIST SP 800-53 or the organisation's own), each "
             "requirement with its evidence, the gaps and what is assessed by hand.",
             "audit", "auditing", sections=[
                 Section("overview", "Overview", "auditing"),
                 Section("requirements", "Requirements", "auditing", "Status and score of each"),
                 Section("gaps", "Gaps", "auditing", "Failing checks, the most urgent first"),
                 Section("manual", "Assessed by hand", "auditing", "And the requirements still to assess"),
                 Section("failed_all", "Every failed check of every asset", "auditing", "As a separate Excel file",
                         default=False, excel_only=True),
             ], options=[Option("standard", "Standard", "choice", "pci-dss-4.0", choices_fn=_standards),
                         Option("group", "Asset group", "choice", "all", choices_fn=_groups)],
             default_period="last_30_days", build=_compliance, uses_period=False),
    Template("end_of_life", "End of life",
             "Operating systems, firmware and server software past (or close to) the end of their vendor's support.",
             "vulnerability", "asset_list", sections=[
                 Section("overview", "Overview", "asset_list"),
                 Section("unsupported", "Unsupported", "asset_list", "No more fixes from the vendor"),
                 Section("extended", "Paid extended support only", "asset_list"),
                 Section("ending", "Ending soon", "asset_list"),
                 Section("unknown", "Not in the catalog", "asset_list", default=False),
                 Section("all", "All software", "asset_list", "As a separate Excel file", default=False,
                         excel_only=True),
             ], default_period="last_30_days", build=_end_of_life, uses_period=False),
)
