import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { duration, formatWhen } from "../../utils/dates.js";
import { Changes, RestoreDetailDrawer, RestoreResult } from "./RestoreDetailDrawer.jsx";
import "../../assets/BackupModule.css";
import { t as tr, n } from "../../i18n";

const GROUPS = [
    ["", tr("All"), "all"],
    ["active", tr("In progress"), "active"],
    ["succeeded", tr("Succeeded"), "succeeded"],
    ["reverted", tr("Reverted"), "reverted"],
    ["failed", tr("Failed"), "failed"],
];
const PERIODS = [[30, tr("Last 30 days")], [90, tr("Last 90 days")], [365, tr("Last 12 months")], [0, tr("All time")]];
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
            .catch((e) => alive && setError(e.response?.data?.detail || tr("Could not load the restore history")));
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
                    <div className="bkm-crumb"><Link to="/backup/overview">{tr("Backup & Restore")}</Link> {" "}{tr("› Restore History")}</div>
                    <h1>{tr("Restore History")}</h1>
                    <p>{tr("Every configuration restore: who ran it and why, what changed on the device, and how it ended.")}</p>
                </div>
            </div>

            <div className="bkm-stats bkm-stats-4">
                <div className="bkm-stat"><b>{n(counts.all ?? "—")}</b><span>{tr("Restores · {{periodLabel}}", { periodLabel })}</span></div>
                <div className="bkm-stat"><b className="bkm-green">{n(counts.succeeded ?? "—")}</b><span>{tr("Succeeded")}</span></div>
                <div className="bkm-stat"><b className="bkm-orange">{n(counts.reverted ?? "—")}</b><span>{tr("Reverted automatically · access or verification failed")}</span></div>
                <div className="bkm-stat"><b className="bkm-red">{n(counts.failed ?? "—")}</b><span>{tr("Failed")}</span></div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={tr("Result")}>
                    {GROUPS.map(([value, label, key]) => (
                        <button key={key} type="button" aria-pressed={group === value}
                                className={`bkm-chip ${group === value ? "is-on" : ""}`}
                                onClick={() => { setGroup(value); setOffset(0); }}>
                            {label} <b>{n(counts[key] ?? 0)}</b>
                        </button>
                    ))}
                </div>
                <div className="bkm-actions">
                    <label className="bkm-search">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                        <input aria-label={tr("Search restores")} placeholder={tr("Device, user or reason")} value={search} maxLength={200}
                               onChange={(e) => { setSearch(e.target.value); setOffset(0); }} />
                    </label>
                    <select className="bkm-select" aria-label={tr("Period")} value={days} onChange={(e) => { setDays(Number(e.target.value)); setOffset(0); }}>
                        {PERIODS.map(([d, label]) => <option key={d} value={d}>{label}</option>)}
                    </select>
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error">{error}</div>}

            <section className="bkm-card bkm-flush">
                {!page ? <div className="bkm-empty">{tr("Loading…")}</div> : page.items.length === 0 ? (
                    <div className="bkm-empty">
                        <b>{counts.all ? tr("No restore matches these filters") : tr("No restores in this period")}</b>
                        <span>{tr("Restores are started from a device's backups in Device Backups.")}</span>
                    </div>
                ) : (
                    <div className="bkm-table-wrap">
                        <table className="bkm-table">
                            <thead>
                                <tr><th>{tr("When")}</th><th>{tr("Device")}</th><th>{tr("Reason")}</th><th>{tr("Restored backup")}</th><th>{tr("Changes")}</th><th>{tr("By")}</th><th>{tr("Result")}</th></tr>
                            </thead>
                            <tbody>
                                {page.items.map((r) => {
                                    const took = duration(r.started_at || r.created_at, r.finished_at);
                                    return (
                                        <tr key={r.id} className="bkm-row-click" tabIndex={0} onClick={() => setOpenId(r.id)}
                                            onKeyDown={(e) => e.key === "Enter" && setOpenId(r.id)}>
                                            <td className="bkm-nowrap">{formatWhen(r.created_at)}{took && <span className="bkm-sub">{tr("took {{took}}", { took })}</span>}</td>
                                            <td className="bkm-nowrap">
                                                <b className="bkm-strong bkm-navy">{r.asset_name || tr("Asset #{{asset_id}}", { asset_id: r.asset_id })}</b>
                                                <span className="bkm-sub"><span className="bkm-mono">{r.device_ip}</span> · {FAMILY[r.device_type] || r.device_type}</span>
                                            </td>
                                            <td><span className="bkm-clip bidi-auto" title={r.reason}>{r.reason}</span></td>
                                            <td className="bkm-nowrap">{r.backup_id ? <span className="bkm-mono">#{r.backup_id}</span> : <span className="bkm-muted">{tr("deleted")}</span>}</td>
                                            <td className="bkm-nowrap">
                                                <Changes diff={r.diff_summary} />
                                                <span className="bkm-sub">
                                                    {r.diff_summary?.sections != null && tr("{{count}} sections · ", { count: r.diff_summary.sections })}
                                                    {r.auto_revert === "armed" ? tr("auto-revert {{revert_minutes}} min", { revert_minutes: r.revert_minutes }) : tr("no auto-revert")}
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
                        <span>{tr("Showing {{from}}–{{to}} of {{total}}", { from, to, total: page.total })}</span>
                        <span className="bkm-actions">
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>{tr("← Previous")}</button>
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={to >= page.total} onClick={() => setOffset(offset + PAGE)}>{tr("Next →")}</button>
                        </span>
                    </div>
                )}
            </section>

            {openId && <RestoreDetailDrawer jobId={openId} onClose={() => setOpenId(null)} onChanged={refresh} />}
        </div>
    );
}

export default RestoreHistory;
