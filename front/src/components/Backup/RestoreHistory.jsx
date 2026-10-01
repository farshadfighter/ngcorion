import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { duration, formatWhen } from "../../utils/dates.js";
import { Changes, RestoreDetailDrawer, RestoreResult } from "./RestoreDetailDrawer.jsx";
import "../../assets/BackupModule.css";

const GROUPS = [
    ["", "All", "all"],
    ["active", "In progress", "active"],
    ["succeeded", "Succeeded", "succeeded"],
    ["reverted", "Reverted", "reverted"],
    ["failed", "Failed", "failed"],
];
const PERIODS = [[30, "Last 30 days"], [90, "Last 90 days"], [365, "Last 12 months"], [0, "All time"]];
const PAGE = 25;
const FAMILY = { cisco: "Cisco", fortinet: "Fortinet", linux: "Linux", apache: "Apache", mongodb: "MongoDB" };

/** Backup & Restore › Restore History. */
export function RestoreHistory() {
    const [group, setGroup] = useState("");
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const [days, setDays] = useState(90);
    const [offset, setOffset] = useState(0);
    const [page, setPage] = useState(null);
    const [error, setError] = useState(null);
    const [openId, setOpenId] = useState(null);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((n) => n + 1), []);

    // Search as you type, without a request per keystroke.
    useEffect(() => {
        const t = setTimeout(() => setQuery(search.trim()), 300);
        return () => clearTimeout(t);
    }, [search]);

    useEffect(() => {
        let alive = true;
        const params = { limit: PAGE, offset };
        if (group) params.status = group;
        if (query) params.search = query;
        if (days) params.days = days; else params.days = 3650;
        api.get("/api/backups/restores/history", { params })
            .then(({ data }) => { if (alive) { setPage(data); setError(null); } })
            .catch((e) => alive && setError(e.response?.data?.detail || "Could not load the restore history"));
        return () => { alive = false; };
    }, [group, query, days, offset, reload]);

    const counts = page?.counts || {};
    const from = page && page.total ? offset + 1 : 0;
    const to = page ? Math.min(offset + PAGE, page.total) : 0;
    const periodLabel = (PERIODS.find(([d]) => d === days) || PERIODS[1])[1].toLowerCase();

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <div className="bkm-crumb"><Link to="/backup/overview">Backup &amp; Restore</Link> › Restore History</div>
                    <h1>Restore History</h1>
                    <p>Every configuration restore: who ran it and why, what changed on the device, and how it ended.</p>
                </div>
            </div>

            <div className="bkm-stats bkm-stats-4">
                <div className="bkm-stat"><b>{counts.all ?? "—"}</b><span>Restores · {periodLabel}</span></div>
                <div className="bkm-stat"><b className="bkm-green">{counts.succeeded ?? "—"}</b><span>Succeeded</span></div>
                <div className="bkm-stat"><b className="bkm-orange">{counts.reverted ?? "—"}</b><span>Reverted automatically · access or verification failed</span></div>
                <div className="bkm-stat"><b className="bkm-red">{counts.failed ?? "—"}</b><span>Failed</span></div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label="Result">
                    {GROUPS.map(([value, label, key]) => (
                        <button key={key} type="button" aria-pressed={group === value}
                                className={`bkm-chip ${group === value ? "is-on" : ""}`}
                                onClick={() => { setGroup(value); setOffset(0); }}>
                            {label} <b>{counts[key] ?? 0}</b>
                        </button>
                    ))}
                </div>
                <div className="bkm-actions">
                    <label className="bkm-search">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                        <input aria-label="Search restores" placeholder="Device, user or reason" value={search} maxLength={200}
                               onChange={(e) => { setSearch(e.target.value); setOffset(0); }} />
                    </label>
                    <select className="bkm-select" aria-label="Period" value={days} onChange={(e) => { setDays(Number(e.target.value)); setOffset(0); }}>
                        {PERIODS.map(([d, label]) => <option key={d} value={d}>{label}</option>)}
                    </select>
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error">{error}</div>}

            <section className="bkm-card bkm-flush">
                {!page ? <div className="bkm-empty">Loading…</div> : page.items.length === 0 ? (
                    <div className="bkm-empty">
                        <b>{counts.all ? "No restore matches these filters" : "No restores in this period"}</b>
                        <span>Restores are started from a device&apos;s backups in Device Backups.</span>
                    </div>
                ) : (
                    <div className="bkm-table-wrap">
                        <table className="bkm-table">
                            <thead>
                                <tr><th>When</th><th>Device</th><th>Reason</th><th>Restored backup</th><th>Changes</th><th>By</th><th>Result</th></tr>
                            </thead>
                            <tbody>
                                {page.items.map((r) => {
                                    const took = duration(r.started_at || r.created_at, r.finished_at);
                                    return (
                                        <tr key={r.id} className="bkm-row-click" tabIndex={0} onClick={() => setOpenId(r.id)}
                                            onKeyDown={(e) => e.key === "Enter" && setOpenId(r.id)}>
                                            <td className="bkm-nowrap">{formatWhen(r.created_at)}{took && <span className="bkm-sub">took {took}</span>}</td>
                                            <td className="bkm-nowrap">
                                                <b className="bkm-strong bkm-navy">{r.asset_name || `Asset #${r.asset_id}`}</b>
                                                <span className="bkm-sub"><span className="bkm-mono">{r.device_ip}</span> · {FAMILY[r.device_type] || r.device_type}</span>
                                            </td>
                                            <td><span className="bkm-clip" title={r.reason}>{r.reason}</span></td>
                                            <td className="bkm-nowrap">{r.backup_id ? <span className="bkm-mono">#{r.backup_id}</span> : <span className="bkm-muted">deleted</span>}</td>
                                            <td className="bkm-nowrap">
                                                <Changes diff={r.diff_summary} />
                                                <span className="bkm-sub">
                                                    {r.diff_summary?.sections != null && `${r.diff_summary.sections} section${r.diff_summary.sections === 1 ? "" : "s"} · `}
                                                    {r.auto_revert === "armed" ? `auto-revert ${r.revert_minutes} min` : "no auto-revert"}
                                                </span>
                                            </td>
                                            <td>{r.requested_by_username || "—"}</td>
                                            <td><RestoreResult status={r.status} short /></td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
                {page && page.total > 0 && (
                    <div className="bkm-card-foot bkm-row-between">
                        <span>Showing {from}–{to} of {page.total}</span>
                        <span className="bkm-actions">
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>← Previous</button>
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={to >= page.total} onClick={() => setOffset(offset + PAGE)}>Next →</button>
                        </span>
                    </div>
                )}
            </section>

            {openId && <RestoreDetailDrawer jobId={openId} onClose={() => setOpenId(null)} onChanged={refresh} />}
        </div>
    );
}

export default RestoreHistory;
