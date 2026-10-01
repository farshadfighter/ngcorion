import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission.js";
import { AssetIcon } from "../shared/AssetIcon.jsx";
import { formatDate, formatWhen, relativeDays } from "../../utils/dates.js";
import NewBackupModal from "./NewBackupModal.jsx";
import { Changes, RestoreDetailDrawer, RestoreResult } from "./RestoreDetailDrawer.jsx";
import "../../assets/BackupModule.css";

const FAMILY_LABEL = { cisco: "Cisco", fortinet: "Fortinet", linux: "Linux", apache: "Apache", mongodb: "MongoDB" };
const ATTENTION_ROWS = 8;

const num = (n) => (n == null ? "—" : Number(n).toLocaleString());


/** Backup & Restore › Overview. */
export function BackupOverview() {
    const navigate = useNavigate();
    const canWrite = usePermission("backup", "write");
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [reload, setReload] = useState(0);
    const [backupFor, setBackupFor] = useState(null);   // {asset} or {} for a new one
    const [restoreId, setRestoreId] = useState(null);
    const [showAll, setShowAll] = useState(false);
    const refresh = useCallback(() => setReload((n) => n + 1), []);

    useEffect(() => {
        let alive = true;
        api.get("/api/backups/overview")
            .then(({ data: d }) => { if (alive) { setData(d); setError(null); } })
            .catch((e) => alive && setError(e.response?.data?.detail || "Could not load the backup overview"));
        return () => { alive = false; };
    }, [reload]);

    const coverage = data && data.supported ? Math.round((data.fresh / data.supported) * 100) : 0;
    const maxDay = data ? Math.max(1, ...data.daily.map((d) => d.manual + d.automatic)) : 1;

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>Backup &amp; Restore</h1>
                    <p>Is every device&apos;s configuration saved, and what was restored recently.</p>
                </div>
                <div className="bkm-actions">
                    <button type="button" className="bkm-btn" onClick={() => navigate("/backup/restores")}>Restore history</button>
                    {canWrite && (
                        <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setBackupFor({})}>
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
                            New backup
                        </button>
                    )}
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {!data && !error && <div className="bkm-card bkm-empty">Loading…</div>}

            {data && (
                <>
                    <div className="bkm-stats">
                        <div className="bkm-stat">
                            <span>Backup coverage</span>
                            <b className="bkm-navy">{data.supported ? `${coverage}%` : "—"}</b>
                            <div className="bkm-meter"><span style={{ width: `${coverage}%` }} /></div>
                            <small>{num(data.fresh)} of {num(data.supported)} supported devices</small>
                        </div>
                        <div className={`bkm-stat ${data.never ? "bkm-stat-warn" : ""}`}>
                            <span>Never backed up</span>
                            <b className={data.never ? "bkm-orange" : ""}>{num(data.never)}</b>
                            <small>No saved configuration at all</small>
                        </div>
                        <div className="bkm-stat">
                            <span>Older than {data.stale_days} days</span>
                            <b className={data.stale ? "bkm-amber" : ""}>{num(data.stale)}</b>
                            <small>No backup since {formatDate(data.stale_before)}</small>
                        </div>
                        <div className="bkm-stat">
                            <span>Backups · last 30 days</span>
                            <b>{num(data.backups_30d.total)}</b>
                            <small>{num(data.backups_30d.manual)} manual · {num(data.backups_30d.hardening)} before hardening · {num(data.backups_30d.pre_restore)} before restore</small>
                        </div>
                        <div className="bkm-stat">
                            <span>Restores · last 30 days</span>
                            <b>{num(data.restores_30d.total)}</b>
                            <small>
                                {num(data.restores_30d.succeeded)} succeeded · {num(data.restores_30d.reverted)} auto-reverted · {num(data.restores_30d.failed)} failed
                            </small>
                        </div>
                    </div>

                    <div className="bkm-grid">
                        <section className="bkm-card bkm-flush">
                            <div className="bkm-card-head">
                                <div>
                                    <h2>Needs a backup</h2>
                                    <p>Supported devices with no backup, or none in the last {data.stale_days} days</p>
                                </div>
                                {data.attention_total > 0 && <span className="bkm-muted bkm-strong">{num(data.attention_total)} device{data.attention_total === 1 ? "" : "s"}</span>}
                            </div>
                            {data.attention.length === 0 ? (
                                <div className="bkm-empty">
                                    <b>Every supported device has a recent backup.</b>
                                    {data.supported === 0 && <span>No device a backup can be taken from was found in the inventory.</span>}
                                </div>
                            ) : (
                                <table className="bkm-table">
                                    <thead><tr><th>Device</th><th>Type</th><th>Last backup</th><th aria-label="Actions" /></tr></thead>
                                    <tbody>
                                        {data.attention.slice(0, showAll ? data.attention.length : ATTENTION_ROWS).map((d) => (
                                            <tr key={d.asset_id}>
                                                <td>
                                                    <span className="bkm-asset">
                                                        <AssetIcon icon={d.icon} size={28} />
                                                        <span><b>{d.asset_name}</b>{d.ip_address && <span className="bkm-sub bkm-mono">{d.ip_address}</span>}</span>
                                                    </span>
                                                </td>
                                                <td>{FAMILY_LABEL[d.family] || d.family}</td>
                                                <td>
                                                    <span className={`bkm-pill ${d.state === "never" ? "bkm-pill-orange" : "bkm-pill-amber"}`}
                                                          title={d.last_backup_at ? formatWhen(d.last_backup_at) : undefined}>
                                                        {d.state === "never" ? "Never" : relativeDays(d.last_backup_at)}
                                                    </span>
                                                </td>
                                                <td className="bkm-right">
                                                    {canWrite && (
                                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setBackupFor({ asset: d })}>Back up now</button>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                            {data.attention_total > ATTENTION_ROWS && (
                                <div className="bkm-card-foot">
                                    {showAll
                                        ? `Showing ${num(data.attention.length)} of ${num(data.attention_total)}`
                                        : `Showing ${ATTENTION_ROWS} of ${num(data.attention_total)}`}{" · "}
                                    <button type="button" className="bkm-link" onClick={() => setShowAll(!showAll)}>
                                        {showAll ? "Show fewer" : "Show all"}
                                    </button>
                                </div>
                            )}
                        </section>

                        <div className="bkm-col">
                            <section className="bkm-card bkm-pad">
                                <h2>Coverage by device type</h2>
                                <p className="bkm-card-sub">Devices with a backup in the last {data.stale_days} days</p>
                                <div className="bkm-bars">
                                    {data.by_family.length === 0 && <span className="bkm-muted">No supported devices yet.</span>}
                                    {data.by_family.map((f) => {
                                        const ratio = f.total ? f.fresh / f.total : 0;
                                        return (
                                            <div key={f.family} className="bkm-bar-row">
                                                <span className="bkm-strong">{f.label}</span>
                                                <span className="bkm-track" title={`${Math.round(ratio * 100)}%`}>
                                                    <span style={{ width: `${Math.round(ratio * 100)}%`, background: ratio >= 0.9 ? "#166534" : ratio >= 0.6 ? "#1e3a5f" : "#c2410c" }} />
                                                </span>
                                                <span className="bkm-mono bkm-right">{f.fresh}/{f.total}</span>
                                            </div>
                                        );
                                    })}
                                </div>
                            </section>

                            <section className="bkm-card bkm-pad">
                                <div className="bkm-row-between">
                                    <h2>Backups per day</h2>
                                    <span className="bkm-muted bkm-small">last 30 days</span>
                                </div>
                                <div className="bkm-chart" role="img"
                                     aria-label={`Backups per day over the last 30 days, ${num(data.backups_30d.total)} in total`}>
                                    {data.daily.map((d) => (
                                        <div key={d.date} className="bkm-day" title={`${formatDate(d.date)}: ${d.manual} manual, ${d.automatic} automatic`}>
                                            <span className="bkm-day-auto" style={{ height: `${(d.automatic / maxDay) * 100}%` }} />
                                            <span className="bkm-day-manual" style={{ height: `${(d.manual / maxDay) * 100}%` }} />
                                        </div>
                                    ))}
                                </div>
                                <div className="bkm-legend">
                                    <span><i style={{ background: "#1e3a5f" }} />Manual</span>
                                    <span><i style={{ background: "#93b4d8" }} />Automatic (before hardening / restore)</span>
                                </div>
                            </section>
                        </div>
                    </div>

                    <section className="bkm-card bkm-flush">
                        <div className="bkm-card-head">
                            <h2>Recent restores</h2>
                            <button type="button" className="bkm-link" onClick={() => navigate("/backup/restores")}>View all →</button>
                        </div>
                        {data.recent_restores.length === 0 ? (
                            <div className="bkm-empty"><span>No restores yet.</span></div>
                        ) : (
                            <table className="bkm-table">
                                <thead><tr><th>When</th><th>Device</th><th>Restored backup</th><th>Changes</th><th>By</th><th>Result</th></tr></thead>
                                <tbody>
                                    {data.recent_restores.map((r) => (
                                        <tr key={r.id} className="bkm-row-click" tabIndex={0} onClick={() => setRestoreId(r.id)}
                                            onKeyDown={(e) => e.key === "Enter" && setRestoreId(r.id)}>
                                            <td className="bkm-nowrap">{formatWhen(r.created_at)}</td>
                                            <td><b className="bkm-strong">{r.asset_name}</b></td>
                                            <td>{r.backup_id ? <span className="bkm-mono">#{r.backup_id}</span> : <span className="bkm-muted">deleted</span>}</td>
                                            <td><Changes diff={r.diff_summary} /></td>
                                            <td>{r.requested_by_username || "—"}</td>
                                            <td><RestoreResult status={r.status} /></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                    </section>
                </>
            )}

            {backupFor && (
                <NewBackupModal
                    assetId={backupFor.asset?.asset_id}
                    assetName={backupFor.asset?.asset_name}
                    deviceType={backupFor.asset?.family}
                    onClose={() => setBackupFor(null)}
                    onSuccess={refresh}
                />
            )}
            {restoreId && <RestoreDetailDrawer jobId={restoreId} onClose={() => setRestoreId(null)} onChanged={refresh} />}
        </div>
    );
}

export default BackupOverview;
