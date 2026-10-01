import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { formatWhen } from "../../utils/dates.js";
import { actionLabel, announceAlertsChanged, MODULES, SEVERITY } from "./alertFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import { t as tr, n } from "../../i18n";
import { tb } from "../../i18n/backendText";

const STATUSES = [["open", tr("Active")], ["acknowledged", tr("Acknowledged")], ["resolved", tr("Resolved")]];
const PAGE = 50;

function stateText(a) {
    if (a.status === "acknowledged") return tr("acknowledged by {{user}}", { user: a.acknowledged_by || tr("someone") });
    if (a.status === "resolved") {
        return a.auto_resolved ? tr("recovered by itself") : tr("resolved by {{user}}", { user: a.resolved_by || tr("someone") });
    }
    return tr("not acknowledged");
}

/** Alerts: what needs attention now, from every module. */
export function AlertsPage() {
    const navigate = useNavigate();
    const canManage = usePermission("system_config", "read");
    const [status, setStatus] = useState("open");
    const [module, setModule] = useState("");
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const [offset, setOffset] = useState(0);
    const [page, setPage] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(null);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((n) => n + 1), []);

    useEffect(() => {
        const t = setTimeout(() => setQuery(search.trim()), 300);
        return () => clearTimeout(t);
    }, [search]);

    useEffect(() => {
        let alive = true;
        const params = { status, limit: PAGE, offset };
        if (module) params.module = module;
        if (query) params.search = query;
        api.get("/api/alerts", { params })
            .then(({ data }) => { if (alive) { setPage(data); setError(null); } })
            .catch((e) => alive && setError(e.response?.data?.detail || tr("Could not load alerts")));
        return () => { alive = false; };
    }, [status, module, query, offset, reload]);

    // New alerts appear without a reload.
    useEffect(() => {
        const timer = setInterval(() => document.visibilityState === "visible" && refresh(), 30000);
        window.addEventListener("alerts:changed", refresh);
        return () => { clearInterval(timer); window.removeEventListener("alerts:changed", refresh); };
    }, [refresh]);

    const act = (alert, verb) => {
        setBusy(`${verb}-${alert.id}`);
        api.post(`/api/alerts/${alert.id}/${verb}`)
            .then(() => { announceAlertsChanged(); refresh(); })
            .catch((e) => setError(e.response?.data?.detail
                || (verb === "acknowledge" ? tr("Could not acknowledge the alert") : tr("Could not resolve the alert"))))
            .finally(() => setBusy(null));
    };

    const stats = page?.stats || {};
    const counts = page?.counts || {};
    const items = page?.items || [];
    const from = page && page.total ? offset + 1 : 0;
    const to = page ? Math.min(offset + PAGE, page.total) : 0;

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>{tr("Alerts")}</h1>
                    <p>{tr("What needs attention now, from every module. Acknowledge an alert to tell the team you are on it.")}</p>
                </div>
            </div>

            <div className="bkm-stats bkm-stats-4">
                <div className={`bkm-stat ${stats.critical_unacknowledged ? "alr-stat-critical" : ""}`}>
                    <b className={stats.critical_unacknowledged ? "bkm-red" : ""}>{n(stats.critical_unacknowledged ?? "—")}</b>
                    <span>{tr("Critical, not acknowledged")}</span>
                </div>
                <div className="bkm-stat"><b className="bkm-orange">{n(stats.warning_open ?? "—")}</b><span>{tr("Warning")}</span></div>
                <div className="bkm-stat"><b>{n(stats.acknowledged ?? "—")}</b><span>{tr("Acknowledged, still active")}</span></div>
                <div className="bkm-stat"><b className="bkm-green">{n(stats.resolved_7d ?? "—")}</b><span>{tr("Resolved · last 7 days")}</span></div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={tr("Filter alerts")}>
                    {STATUSES.map(([value, label]) => (
                        <button key={value} type="button" aria-pressed={status === value}
                                className={`bkm-chip ${status === value ? "is-on" : ""}`}
                                onClick={() => { setStatus(value); setOffset(0); }}>
                            {label} <b>{n(counts[value] ?? 0)}</b>
                        </button>
                    ))}
                    <span className="alr-sep" aria-hidden="true" />
                    {(page?.modules || []).map((m) => (
                        <button key={m.key} type="button" aria-pressed={module === m.key}
                                className={`bkm-chip ${module === m.key ? "is-on" : ""}`}
                                onClick={() => { setModule(module === m.key ? "" : m.key); setOffset(0); }}>
                            {MODULES[m.key] || m.label}{m.count ? <b>{n(m.count)}</b> : null}
                        </button>
                    ))}
                </div>
                <div className="bkm-row-gap">
                    <label className="bkm-search">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                        <input value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
                               placeholder={tr("Search alerts, devices…")} aria-label={tr("Search alerts")} />
                    </label>
                    {canManage && <Link className="bkm-btn" to="/settings/notifications">{tr("Notification rules")}</Link>}
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table alr-table">
                        <thead>
                            <tr>
                                <th style={{ width: 96 }}>{tr("Severity")}</th>
                                <th>{tr("Alert")}</th>
                                <th style={{ width: 200 }}>{tr("Source")}</th>
                                <th style={{ width: 160 }}>{status === "resolved" ? tr("Resolved") : tr("Since")}</th>
                                <th style={{ width: 320 }}><span className="sr-only">{tr("Actions")}</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((a) => (
                                <tr key={a.id} className={a.status === "active" && a.severity === "critical" ? "alr-row-critical" : ""}>
                                    <td><span className={`bkm-pill ${SEVERITY[a.severity]?.pill || ""}`}>{SEVERITY[a.severity]?.label || a.severity}</span></td>
                                    <td>
                                        <b className="bkm-strong">{tb(a.title)}</b>
                                        {a.detail && <span className="bkm-sub alr-detail bidi-auto">{tb(a.detail)}</span>}
                                    </td>
                                    <td>
                                        {MODULES[a.module] || a.module}
                                        {a.source && <span className="bkm-sub bkm-mono alr-clip" title={a.source}>{a.source}</span>}
                                    </td>
                                    <td>
                                        {formatWhen(status === "resolved" ? a.resolved_at : a.first_seen_at)}
                                        <span className="bkm-sub">{stateText(a)}</span>
                                    </td>
                                    <td>
                                        <div className="alr-row-actions">
                                            {a.link && (
                                                <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => navigate(a.link)}>
                                                    {actionLabel(a)}
                                                </button>
                                            )}
                                            {a.status === "active" && (
                                                <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary"
                                                        disabled={busy === `acknowledge-${a.id}`} onClick={() => act(a, "acknowledge")}>
                                                    {tr("Acknowledge")}
                                                </button>
                                            )}
                                            {a.status !== "resolved" && (a.kind === "event" || a.status === "acknowledged") && (
                                                <button type="button" className="bkm-btn bkm-btn-sm" title={a.kind === "state"
                                                    ? tr("Closes the alert now. If the problem is still there, a new alert is raised at the next check.")
                                                    : tr("Close this alert")}
                                                        disabled={busy === `resolve-${a.id}`} onClick={() => act(a, "resolve")}>
                                                    {tr("Resolve")}
                                                </button>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {page && items.length === 0 && (
                    <div className="bkm-empty">
                        <b>{status === "resolved" ? tr("No resolved alerts") : query || module ? tr("No alert matches") : tr("All clear")}</b>
                        <span className="bkm-muted">
                            {status === "open" && !query && !module
                                ? tr("Nothing needs attention right now. New alerts appear here and on the bell.")
                                : tr("Try another filter.")}
                        </span>
                    </div>
                )}
                {page && page.total > PAGE && (
                    <div className="bkm-card-foot bkm-row-between">
                        <span>{tr("{{from}}–{{to}} of {{total}}", { from, to, total: page.total })}</span>
                        <span className="bkm-actions">
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={offset === 0}
                                    onClick={() => setOffset(Math.max(0, offset - PAGE))}>{tr("Previous")}</button>
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={to >= page.total}
                                    onClick={() => setOffset(offset + PAGE)}>{tr("Next")}</button>
                        </span>
                    </div>
                )}
            </section>
        </div>
    );
}
