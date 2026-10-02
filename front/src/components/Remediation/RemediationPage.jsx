import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { t, n } from "../../i18n";
import { RemediationDrawer } from "./RemediationDrawer.jsx";
import { SEVERITY, SOURCE, STATUS, count, dueClass, dueText, itemTitle, shortDate } from "./remediationFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Remediation.css";

const VIEWS = [
    ["open", t("Open")],
    ["overdue", t("Overdue")],
    ["in_progress", t("In progress")],
    ["pending_verification", t("Awaiting verification")],
    ["unassigned", t("Unassigned")],
    ["mine", t("Assigned to me")],
    ["accepted", t("Risk accepted")],
    ["resolved", t("Fixed")],
];
const PAGE = 50;

/** Remediation: every open finding from every module, with an owner and a deadline. */
export function RemediationPage() {
    const canWrite = usePermission("remediation", "write");
    const [params, setParams] = useSearchParams();
    const [view, setView] = useState("open");
    const [source, setSource] = useState("");
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const [offset, setOffset] = useState(0);
    const [page, setPage] = useState(null);
    const [summary, setSummary] = useState(null);
    const [error, setError] = useState(null);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((x) => x + 1), []);
    const openId = Number(params.get("item")) || null;

    // Bring the list up to date with the modules once when the page opens.
    useEffect(() => {
        if (!canWrite) return;
        api.post("/api/remediation/sync").then(refresh).catch(() => {});
    }, [canWrite, refresh]);

    useEffect(() => {
        const timer = setTimeout(() => setQuery(search.trim()), 300);
        return () => clearTimeout(timer);
    }, [search]);

    useEffect(() => {
        let alive = true;
        const p = { view, offset, limit: PAGE };
        if (source) p.source = source;
        if (query) p.q = query;
        Promise.all([api.get("/api/remediation/items", { params: p }), api.get("/api/remediation/summary")])
            .then(([items, s]) => { if (alive) { setPage(items.data); setSummary(s.data); setError(null); } })
            .catch(() => alive && setError(t("Could not load the findings")));
        return () => { alive = false; };
    }, [view, source, query, offset, reload]);

    const openItem = (id) => setParams(id ? { item: String(id) } : {});
    const s = summary || {};
    const statusCounts = s.counts?.status || {};
    const viewCount = {
        open: s.open, overdue: s.overdue, in_progress: statusCounts.in_progress,
        pending_verification: statusCounts.pending_verification, unassigned: s.counts?.unassigned,
        accepted: statusCounts.accepted, resolved: statusCounts.resolved,
    };
    const items = page?.items || [];
    const from = page && page.total ? offset + 1 : 0;
    const to = page ? Math.min(offset + PAGE, page.total) : 0;

    return (
        <div className="bkm-page">
            <div className="bkm-head rem-head">
                <div>
                    <h1>{t("Remediation Tracking")}</h1>
                    <p>{t("Every open finding from CVE, audits and architecture validation, with an owner and a deadline. A finding closes by itself when the next audit or CVE check no longer reports it.")}</p>
                </div>
                <Link className="bkm-btn" to="/remediation/acceptances">{t("Accepted Risks")}</Link>
            </div>

            <div className="bkm-stats rem-stats">
                <div className="bkm-stat"><b>{count(s.open)}</b><span>{t("Open findings")}</span></div>
                <div className={`bkm-stat ${s.overdue ? "alr-stat-critical" : ""}`}>
                    <b className={s.overdue ? "bkm-red" : ""}>{count(s.overdue)}</b><span>{t("Past the deadline")}</span>
                </div>
                <div className="bkm-stat"><b className={s.due_soon ? "bkm-orange" : ""}>{count(s.due_soon)}</b><span>{t("Due within 7 days")}</span></div>
                <div className="bkm-stat">
                    <b>{s.on_time_pct == null ? "—" : n(`${s.on_time_pct}%`)}</b>
                    <span>{t("Fixed on time · last 90 days")}</span>
                </div>
                <div className="bkm-stat">
                    <b>{s.mttr_days == null ? "—" : t("{{days}} days", { days: s.mttr_days })}</b>
                    <span>{t("Average time to fix")}</span>
                </div>
                <div className="bkm-stat">
                    <b className="rem-violet">{count(s.accepted)}</b>
                    <span>{s.acceptances_pending
                        ? t("Risk accepted · {{pending}} awaiting approval", { pending: s.acceptances_pending })
                        : t("Risk accepted")}</span>
                </div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={t("Filter findings")}>
                    {VIEWS.map(([value, label]) => (
                        <button key={value} type="button" aria-pressed={view === value}
                                className={`bkm-chip ${view === value ? "is-on" : ""}`}
                                onClick={() => { setView(value); setOffset(0); }}>
                            {label}{viewCount[value] != null && value !== "mine" ? <b>{count(viewCount[value])}</b> : null}
                        </button>
                    ))}
                    <span className="alr-sep" aria-hidden="true" />
                    {Object.entries(SOURCE).map(([key, label]) => (
                        <button key={key} type="button" aria-pressed={source === key}
                                className={`bkm-chip ${source === key ? "is-on" : ""}`}
                                onClick={() => { setSource(source === key ? "" : key); setOffset(0); }}>
                            {label}{s.counts?.source?.[key] ? <b>{count(s.counts.source[key])}</b> : null}
                        </button>
                    ))}
                </div>
                <label className="bkm-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
                           placeholder={t("Search finding, asset or ID…")} aria-label={t("Search findings")} />
                </label>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table rem-table rem-list-table">
                        <thead>
                            <tr>
                                <th style={{ width: 80 }}>{t("Severity")}</th>
                                <th>{t("Finding")}</th>
                                <th style={{ width: 140 }}>{t("Asset")}</th>
                                <th style={{ width: 70 }}>{t("Source")}</th>
                                <th style={{ width: 100 }}>{t("Owner")}</th>
                                <th style={{ width: 120 }}>{view === "resolved" ? t("Closed") : t("Deadline")}</th>
                                <th style={{ width: 125 }}>{t("Status")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((i) => (
                                <tr key={i.id} className={`bkm-row-click ${openId === i.id ? "rem-row-on" : ""}`}
                                    onClick={() => openItem(i.id)} tabIndex={0}
                                    onKeyDown={(e) => e.key === "Enter" && openItem(i.id)}>
                                    <td><span className={`bkm-pill ${SEVERITY[i.severity]?.pill}`}>{SEVERITY[i.severity]?.label || i.severity}</span></td>
                                    <td>
                                        <div className="rem-title">
                                            {i.source !== "arch" && <span className="bkm-mono rem-ref">{i.ref}</span>}
                                            {i.kev && <span className="bkm-pill rem-kev">{t("Exploited in the wild")}</span>}
                                        </div>
                                        <span className="bkm-sub rem-clip bidi-auto" title={i.title}>{itemTitle(i)}</span>
                                    </td>
                                    <td>{i.asset_name || "—"}{i.ip_address && <span className="bkm-sub bkm-mono">{i.ip_address}</span>}</td>
                                    <td className="bkm-muted">{SOURCE[i.source] || i.source}</td>
                                    <td>{i.owner || <span className="bkm-muted">{t("Unassigned")}</span>}</td>
                                    <td>
                                        {view === "resolved"
                                            ? shortDate(i.resolved_at)
                                            : i.status === "accepted"
                                                ? (i.acceptance ? t("until {{date}}", { date: shortDate(i.acceptance.expires_at) }) : "—")
                                                : <span className={dueClass(i)}>{shortDate(i.due_at)}<span className="bkm-sub">{dueText(i)}</span></span>}
                                    </td>
                                    <td><span className={`bkm-pill ${STATUS[i.status]?.pill}`}>{STATUS[i.status]?.label || i.status}</span></td>
                                </tr>
                            ))}
                            {page && items.length === 0 && (
                                <tr><td colSpan={7}>
                                    <div className="bkm-empty">
                                        <b>{view === "open" && !query && !source ? t("Nothing to fix right now") : t("No finding matches these filters")}</b>
                                        <span>{t("Findings appear here after audits, CVE checks and architecture validation.")}</span>
                                    </div>
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
                {page && page.total > PAGE && (
                    <div className="bkm-card-foot bkm-row-between">
                        <span>{t("{{from}}–{{to}} of {{total}}", { from, to, total: page.total })}</span>
                        <div className="bkm-actions">
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>{t("Previous")}</button>
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={to >= page.total} onClick={() => setOffset(offset + PAGE)}>{t("Next")}</button>
                        </div>
                    </div>
                )}
            </section>

            {openId && <RemediationDrawer key={openId} itemId={openId} canWrite={canWrite} onClose={() => openItem(null)} onChanged={refresh} />}
        </div>
    );
}
