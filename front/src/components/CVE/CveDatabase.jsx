import { useCallback, useEffect, useRef, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { fetchCveDbStatus, fetchCveJobs } from "../../store/cveSlice.jsx";
import { KIND_LABEL, formatBytes, formatDate, formatWhen, num } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";
import { CveJobModal } from "./CveJobModal.jsx";
import { CvePackageImport } from "./CvePackageImport.jsx";
import { CveExportModal } from "./CveExportModal.jsx";
import "../../assets/Cve.css";

const TIMES = Array.from({ length: 48 }, (_, i) => `${String(Math.floor(i / 2)).padStart(2, "0")}:${i % 2 ? "30" : "00"}`);

const RESULT = {
    succeeded: { label: "Succeeded", cls: "cvx-pill-ok" },
    failed: { label: "Failed", cls: "cvx-pill-bad" },
    cancelled: { label: "Cancelled", cls: "cvx-pill-muted" },
    running: { label: "Running", cls: "cvx-pill-run" },
    queued: { label: "Queued", cls: "cvx-pill-run" },
};

const host = (url) => { try { return new URL(url).host; } catch { return url; } };

function nextRun(auto) {
    if (!auto?.enabled) return "Off";
    const [h, m] = auto.time.split(":").map(Number);
    const now = new Date();
    const passed = now.getHours() * 60 + now.getMinutes() >= h * 60 + m;
    return `${passed ? "Tomorrow" : "Today"} ${auto.time}`;
}

function methodLabel(job) {
    const base = KIND_LABEL[job.kind] || job.kind;
    if (job.kind === "online") return job.trigger === "automatic" ? "Online · automatic" : "Online · manual";
    return base;
}

export function CveDatabase() {
    const dispatch = useDispatch();
    const { status, statusError, jobs } = useSelector((s) => s.cve);
    const [jobId, setJobId] = useState(null);
    const [importFile, setImportFile] = useState(null);
    const [showExport, setShowExport] = useState(false);
    const [message, setMessage] = useState(null);

    const refresh = useCallback(() => {
        dispatch(fetchCveDbStatus());
        dispatch(fetchCveJobs());
    }, [dispatch]);

    useEffect(() => { refresh(); }, [refresh]);

    // While a job runs elsewhere (another admin, the daily update) keep the page current.
    const running = status?.active_job;
    useEffect(() => {
        if (!running || jobId) return undefined;
        const t = setInterval(refresh, 4000);
        return () => clearInterval(t);
    }, [running, jobId, refresh]);

    const isAdmin = !!status?.is_admin;
    const busy = !!running;

    const startUpdate = async (full) => {
        if (full && !window.confirm("Download every CVE again? The current data stays in use until the download finishes. Without an NVD API key this takes about 20 minutes.")) return;
        setMessage(null);
        try {
            const { data } = await api.post("/api/cve/db/update", { full });
            setJobId(data.id);
        } catch (err) {
            setMessage({ type: "error", text: err.response?.data?.detail || "The update could not be started" });
        }
    };

    const closeJob = () => { setJobId(null); refresh(); };

    if (!status) {
        return (
            <div className="cvx-page">
                <PageHead />
                {statusError ? <div className="cvx-note cvx-note-error">{statusError}</div> : <div className="cvx-muted">Loading…</div>}
            </div>
        );
    }

    const last = status.last_job;
    const lastOk = jobs.find((j) => j.status === "succeeded" && j.kind !== "export");

    return (
        <div className="cvx-page">
            <PageHead />

            {running && !jobId && (
                <div className="cvx-banner">
                    <span className="cvx-spin" />
                    <span><b>{KIND_LABEL[running.kind]} in progress</b>{running.trigger === "automatic" ? " · automatic" : running.requested_by_name ? ` · started by ${running.requested_by_name}` : ""}</span>
                    <button type="button" className="cvx-btn cvx-btn-sm" onClick={() => setJobId(running.id)}>View progress</button>
                </div>
            )}
            {message && <div className={`cvx-note ${message.type === "error" ? "cvx-note-error" : "cvx-note-ok"}`}>{message.text}</div>}

            <div className="cvx-stats cvx-stats-4">
                <div className="cvx-stat">
                    <b>{num(status.cves)}</b>
                    <span>CVE records</span>
                    <small>{status.loaded ? `${num(status.with_cpe)} with product data · source NVD` : "Not loaded yet"}</small>
                </div>
                <div className="cvx-stat">
                    <b>{num(status.kev)}</b>
                    <span>Known exploited (CISA KEV)</span>
                    <small>{status.kev_released ? `List of ${formatDate(status.kev_released)}` : "—"}</small>
                </div>
                <div className="cvx-stat">
                    <b className={status.loaded ? "cvx-good" : ""}>{status.watermark ? formatWhen(status.watermark) : "Never"}</b>
                    <span>Up to date as of</span>
                    <small>{lastOk ? `${methodLabel(lastOk)} · +${num(lastOk.stats?.new || 0)} new · ${num(lastOk.stats?.changed || 0)} changed` : "No update yet"}</small>
                </div>
                <div className="cvx-stat">
                    <b>{formatBytes(status.size_bytes)}</b>
                    <span>Database size</span>
                    <small>{status.epss_date ? `EPSS scores of ${formatDate(status.epss_date)}` : "No EPSS scores yet"}</small>
                </div>
            </div>

            {!isAdmin && (
                <div className="cvx-note">Only administrators can update the CVE database. Findings use the copy shown here.</div>
            )}

            {isAdmin && (
                <div className="cvx-grid-2">
                    <OnlineCard status={status} busy={busy} onUpdate={startUpdate} onSaved={refresh} />
                    <OfflineCard busy={busy} onFile={setImportFile} onExport={() => setShowExport(true)} loaded={status.loaded} />
                </div>
            )}

            {isAdmin && <TrustedKeys />}

            <section className="cvx-card cvx-card-flush">
                <div className="cvx-card-title">Update history</div>
                {jobs.length === 0 ? (
                    <div className="cvx-empty-row">No updates yet.</div>
                ) : (
                    <div className="cvx-table-wrap">
                        <table className="cvx-table">
                            <thead>
                                <tr><th>When</th><th>Method</th><th className="cvx-num">New</th><th className="cvx-num">Changed</th><th className="cvx-num">KEV</th><th>By</th><th>Result</th></tr>
                            </thead>
                            <tbody>
                                {jobs.map((j) => {
                                    const r = RESULT[j.status] || RESULT.failed;
                                    const export_ = j.kind === "export";
                                    return (
                                        <tr key={j.id} className="cvx-row-click" tabIndex={0}
                                            onClick={() => setJobId(j.id)}
                                            onKeyDown={(e) => e.key === "Enter" && setJobId(j.id)}>
                                            <td>{formatWhen(j.finished_at || j.started_at || j.created_at)}</td>
                                            <td>
                                                <div>{methodLabel(j)}</div>
                                                {j.file_name && <div className="cvx-sub cvx-mono">{j.file_name}</div>}
                                            </td>
                                            <td className="cvx-num">{export_ || j.status !== "succeeded" ? "—" : num(j.stats?.new || 0)}</td>
                                            <td className="cvx-num">{export_ || j.status !== "succeeded" ? "—" : num(j.stats?.changed || 0)}</td>
                                            <td className="cvx-num">{j.status === "succeeded" && j.stats?.kev != null ? num(j.stats.kev) : "—"}</td>
                                            <td>{j.requested_by_name || (j.trigger === "automatic" ? "Automatic" : "—")}</td>
                                            <td>
                                                <span className={`cvx-pill ${r.cls}`} title={j.error || undefined}>{r.label}</span>
                                                {j.status === "failed" && j.error && <div className="cvx-sub cvx-clip" title={j.error}>{j.error}</div>}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
            {last && last.status === "failed" && !running && (
                <div className="cvx-muted cvx-small">The last update failed; the database still holds the data from before it.</div>
            )}

            {jobId && <CveJobModal jobId={jobId} isAdmin={isAdmin} onClose={closeJob} />}
            {importFile && (
                <CvePackageImport file={importFile} onClose={() => setImportFile(null)}
                                  onStarted={(job) => { setImportFile(null); setJobId(job.id); }} />
            )}
            {showExport && (
                <CveExportModal onClose={() => setShowExport(false)}
                                onStarted={(job) => { setShowExport(false); setJobId(job.id); }} />
            )}
        </div>
    );
}

function PageHead() {
    return (
        <div className="cvx-head">
            <div>
                <div className="cvx-crumb"><Link to="/cve">CVE</Link> › Database</div>
                <h1>CVE Database</h1>
                <p>A local copy of every published CVE, so matching works without internet. Update it online, or with a package on air-gapped networks.</p>
            </div>
        </div>
    );
}

function OnlineCard({ status, busy, onUpdate, onSaved }) {
    const [editingKey, setEditingKey] = useState(false);
    const [key, setKey] = useState("");
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [conn, setConn] = useState(null);
    const [testing, setTesting] = useState(false);
    const auto = status.auto_update;

    const save = async (body) => {
        setSaving(true);
        setError(null);
        try {
            await api.put("/api/cve/db/settings", body);
            setEditingKey(false);
            setKey("");
            onSaved();
        } catch (err) {
            setError(err.response?.data?.detail || "Could not save");
        } finally {
            setSaving(false);
        }
    };

    const test = async () => {
        setTesting(true);
        setConn(null);
        try {
            setConn((await api.post("/api/cve/db/test-connection", {}, { timeout: 0 })).data);
        } catch (err) {
            setConn({ ok: false, checks: [{ name: "NGCorion", ok: false, detail: err.response?.data?.detail || "The test could not run" }] });
        } finally {
            setTesting(false);
        }
    };

    return (
        <section className="cvx-card cvx-col">
            <div className="cvx-card-head">
                <span className="cvx-tile" style={{ background: "#1d4ed8" }}><Icon name="cloud" size={22} stroke="#fff" width={1.8} /></span>
                <div>
                    <h2>Update online</h2>
                    <p>{status.loaded ? "Downloads only what changed since the last update." : "Downloads every published CVE, then keeps it current."}</p>
                </div>
            </div>
            <div>
                <div className="cvx-row"><span>Sources</span><b>NVD · CISA KEV · FIRST EPSS</b></div>
                <div className="cvx-row">
                    <span>NVD API key</span>
                    {!editingKey ? (
                        <b className={status.api_key_configured ? "cvx-good" : "cvx-warn"}>
                            {status.api_key_configured ? "Configured" : "Not set · updates are slower"}
                            <button type="button" className="cvx-link" onClick={() => setEditingKey(true)}>{status.api_key_configured ? "Change" : "Add"}</button>
                            {status.api_key_configured && (
                                <button type="button" className="cvx-link cvx-link-danger" disabled={saving} onClick={() => save({ clear_api_key: true })}>Remove</button>
                            )}
                        </b>
                    ) : (
                        <form className="cvx-inline-form" onSubmit={(e) => { e.preventDefault(); if (key.trim()) save({ nvd_api_key: key.trim() }); }}>
                            <input className="cvx-input" type="password" autoComplete="off" placeholder="Paste the API key" aria-label="NVD API key"
                                   value={key} onChange={(e) => setKey(e.target.value)} maxLength={64} />
                            <button type="submit" className="cvx-btn cvx-btn-sm cvx-btn-primary" disabled={saving || !key.trim()}>Save</button>
                            <button type="button" className="cvx-btn cvx-btn-sm" onClick={() => { setEditingKey(false); setKey(""); }}>Cancel</button>
                        </form>
                    )}
                </div>
                {editingKey && (
                    <div className="cvx-hint">Free from <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noreferrer">nvd.nist.gov</a>. Stored encrypted; never shown again.</div>
                )}
                <div className="cvx-row">
                    <span>Connection</span>
                    <b>
                        {conn ? (
                            <span className={conn.ok ? "cvx-good" : "cvx-bad"}>{conn.ok ? `${host(status.sources.nvd)} reachable` : "Not reachable"}</span>
                        ) : <span className="cvx-muted">Not tested</span>}
                        <button type="button" className="cvx-link" onClick={test} disabled={testing}>{testing ? "Testing…" : "Test"}</button>
                    </b>
                </div>
                {conn && (
                    <ul className="cvx-conn">
                        {conn.checks.map((c) => (
                            <li key={c.name}><Icon name={c.ok ? "check" : "x"} size={14} stroke={c.ok ? "#166534" : "#b91c1c"} width={2.4} /><b>{c.name}</b> {c.detail}</li>
                        ))}
                    </ul>
                )}
                <div className="cvx-row cvx-row-last"><span>Next automatic update</span><b>{status.loaded ? nextRun(auto) : "After the first load"}</b></div>
            </div>
            <label className="cvx-check">
                <input type="checkbox" checked={auto.enabled} disabled={saving}
                       onChange={(e) => save({ auto_update_enabled: e.target.checked })} />
                Update automatically every day at
                <select className="cvx-select" aria-label="Automatic update time" value={auto.time} disabled={saving}
                        onChange={(e) => save({ auto_update_time: e.target.value })}>
                    {(TIMES.includes(auto.time) ? TIMES : [auto.time, ...TIMES]).map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <span className="cvx-muted cvx-small">server time</span>
            </label>
            {error && <div className="cvx-note cvx-note-error">{error}</div>}
            <div className="cvx-actions">
                <button type="button" className="cvx-btn cvx-btn-primary" disabled={busy} onClick={() => onUpdate(false)}>
                    <Icon name="refresh" size={16} /> {status.loaded ? "Update now" : "Download the database"}
                </button>
                {status.loaded && (
                    <button type="button" className="cvx-link" disabled={busy} onClick={() => onUpdate(true)}>Download everything again</button>
                )}
            </div>
        </section>
    );
}

function OfflineCard({ busy, onFile, onExport, loaded }) {
    const input = useRef(null);
    const [over, setOver] = useState(false);

    const pick = (files) => {
        const f = files?.[0];
        if (f) onFile(f);
    };

    return (
        <section className="cvx-card cvx-col">
            <div className="cvx-card-head">
                <span className="cvx-tile" style={{ background: "#334155" }}><Icon name="package" size={22} stroke="#fff" width={1.8} /></span>
                <div>
                    <h2>Update offline</h2>
                    <p>For servers without internet access.</p>
                </div>
            </div>
            <label className={`cvx-drop ${over ? "is-over" : ""} ${busy ? "is-disabled" : ""}`}
                   onDragOver={(e) => { e.preventDefault(); if (!busy) setOver(true); }}
                   onDragLeave={() => setOver(false)}
                   onDrop={(e) => { e.preventDefault(); setOver(false); if (!busy) pick(e.dataTransfer.files); }}>
                <input ref={input} type="file" accept=".ngcve" className="cvx-sr" disabled={busy}
                       onChange={(e) => { pick(e.target.files); e.target.value = ""; }} />
                <Icon name="upload" size={26} stroke="#1e3a5f" width={1.8} />
                <b>Drop an update package here, or browse</b>
                <span>.ngcve file · signed packages only · checked before anything is imported</span>
            </label>
            <div className="cvx-callout">
                <div><b>Have a second NGCorion online?</b><br />Export a package there and carry it over.</div>
                <button type="button" className="cvx-btn cvx-btn-sm" onClick={onExport} disabled={busy || !loaded}
                        title={loaded ? undefined : "Load the database first"}>Create package</button>
            </div>
        </section>
    );
}

function TrustedKeys() {
    const [keys, setKeys] = useState([]);
    const [name, setName] = useState("");
    const [pub, setPub] = useState("");
    const [error, setError] = useState(null);
    const [copied, setCopied] = useState(null);
    const [adding, setAdding] = useState(false);

    const load = useCallback(() => {
        api.get("/api/cve/db/keys").then(({ data }) => setKeys(data)).catch(() => {});
    }, []);
    useEffect(() => { load(); }, [load]);

    const add = async (e) => {
        e.preventDefault();
        setError(null);
        try {
            await api.post("/api/cve/db/keys", { name: name.trim(), public_key: pub.trim() });
            setName(""); setPub(""); setAdding(false);
            load();
        } catch (err) {
            setError(err.response?.data?.detail?.[0]?.msg || err.response?.data?.detail || "The key could not be added");
        }
    };

    const remove = async (k) => {
        if (!window.confirm(`Stop trusting packages signed by "${k.name}"?`)) return;
        await api.delete(`/api/cve/db/keys/${k.id}`).catch(() => {});
        load();
    };

    const copy = async (k) => {
        try {
            await navigator.clipboard.writeText(k.public_key);
            setCopied(k.fingerprint);
            setTimeout(() => setCopied(null), 2000);
        } catch {
            window.prompt("Public key", k.public_key);
        }
    };

    return (
        <section className="cvx-card cvx-card-flush">
            <div className="cvx-card-title cvx-card-title-row">
                <div>
                    Trusted keys
                    <div className="cvx-sub">Packages are imported only when signed by one of these.</div>
                </div>
                {!adding && <button type="button" className="cvx-btn cvx-btn-sm" onClick={() => setAdding(true)}><Icon name="plus" size={15} /> Add key</button>}
            </div>
            {adding && (
                <form className="cvx-key-form" onSubmit={add}>
                    <input className="cvx-input" placeholder="Name, e.g. HQ NGCorion" aria-label="Key name" value={name} maxLength={120}
                           onChange={(e) => setName(e.target.value)} />
                    <input className="cvx-input cvx-mono" placeholder="Public key (base64), from the exporting server's Trusted keys" aria-label="Public key"
                           value={pub} maxLength={100} onChange={(e) => setPub(e.target.value)} />
                    <button type="submit" className="cvx-btn cvx-btn-sm cvx-btn-primary" disabled={!name.trim() || !pub.trim()}>Add</button>
                    <button type="button" className="cvx-btn cvx-btn-sm" onClick={() => { setAdding(false); setError(null); }}>Cancel</button>
                </form>
            )}
            {error && <div className="cvx-note cvx-note-error cvx-m">{String(error)}</div>}
            <div className="cvx-table-wrap">
                <table className="cvx-table">
                    <thead><tr><th>Name</th><th>Fingerprint</th><th>Type</th><th aria-label="Actions" /></tr></thead>
                    <tbody>
                        {keys.map((k) => (
                            <tr key={k.fingerprint}>
                                <td><span className="cvx-keyname"><Icon name="key" size={15} stroke="#475569" />{k.name}</span></td>
                                <td className="cvx-mono" title={k.fingerprint}>{k.fingerprint.slice(0, 32).match(/.{4}/g).join(" ")}…</td>
                                <td>{k.builtin ? <span className="cvx-pill cvx-pill-muted">Built in</span> : <span className="cvx-pill cvx-pill-blue">Added</span>}</td>
                                <td className="cvx-right">
                                    <button type="button" className="cvx-link" onClick={() => copy(k)}>
                                        {copied === k.fingerprint ? "Copied" : "Copy public key"}
                                    </button>
                                    {!k.builtin && <button type="button" className="cvx-link cvx-link-danger" onClick={() => remove(k)}>Remove</button>}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </section>
    );
}

export default CveDatabase;
