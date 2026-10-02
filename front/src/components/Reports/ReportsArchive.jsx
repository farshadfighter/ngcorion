import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDateTime, formatWhen } from "../../utils/dates.js";
import { STATUS, download, errorText, fileSize, periodText } from "./reportFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Reports.css";

const VIEWS = [
    ["all", t("All")],
    ["mine", t("Built by me")],
    ["scheduled", t("Scheduled")],
    ["running", t("Being built")],
    ["failed", t("Failed")],
    ["pinned", t("Pinned")],
];

/** Every report built, with who asked, the files, their hash, and what can be done with them. */
export function ReportsArchive() {
    const canWrite = usePermission("reports", "write");
    const canDelete = usePermission("reports", "delete");
    const [params] = useSearchParams();
    const highlight = Number(params.get("new")) || null;
    const [view, setView] = useState("all");
    const [search, setSearch] = useState("");
    const [query, setQuery] = useState("");
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(null);
    const [confirm, setConfirm] = useState(null);
    const [verifying, setVerifying] = useState(false);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((x) => x + 1), []);

    useEffect(() => {
        const timer = setTimeout(() => setQuery(search.trim()), 300);
        return () => clearTimeout(timer);
    }, [search]);

    useEffect(() => {
        let alive = true;
        api.get("/api/reports", { params: { view, q: query || undefined, limit: 100 } })
            .then(({ data: d }) => { if (alive) { setData(d); setError(null); } })
            .catch(() => alive && setError(t("Could not load the reports")));
        return () => { alive = false; };
    }, [view, query, reload]);

    // While something is being built, look again every few seconds.
    const pending = (data?.items || []).some((r) => r.status === "queued" || r.status === "running");
    useEffect(() => {
        if (!pending) return undefined;
        const timer = setInterval(refresh, 3000);
        return () => clearInterval(timer);
    }, [pending, refresh]);

    const act = (r, fn, fallback) => {
        setBusy(r.id);
        setError(null);
        fn().then(refresh).catch((e) => setError(errorText(e, fallback))).finally(() => setBusy(null));
    };
    const get = (r, kind) => {
        setBusy(r.id);
        download(r, kind).catch(() => setError(t("Could not download the file"))).finally(() => setBusy(null));
    };

    const items = data?.items || [];
    const counts = data?.counts || {};

    return (
        <div className="bkm-page">
            <div className="bkm-head rep-head">
                <div>
                    <div className="bkm-crumb"><Link to="/reports">{t("Reports")}</Link> › {t("Archive")}</div>
                    <h1>{t("Report archive")}</h1>
                    <p>{t("Every report built, with its settings, who asked for it and the SHA-256 of its files. Reports are kept for the period set in System Configuration; a pinned report is never deleted.")}</p>
                </div>
                <button type="button" className="bkm-btn" onClick={() => setVerifying(true)}>{t("Check a file…")}</button>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={t("Filter reports")}>
                    {VIEWS.map(([v, l]) => (
                        <button key={v} type="button" aria-pressed={view === v} className={`bkm-chip ${view === v ? "is-on" : ""}`}
                                onClick={() => setView(v)}>{l} <b>{n(counts[v] ?? 0)}</b></button>
                    ))}
                </div>
                <label className="bkm-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("Search title or ID…")} aria-label={t("Search reports")} />
                </label>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table rep-table">
                        <thead>
                            <tr>
                                <th>{t("Report")}</th>
                                <th style={{ width: 110 }}>{t("Period")}</th>
                                <th style={{ width: 150 }}>{t("Built")}</th>
                                <th style={{ width: 140 }}>{t("Files")}</th>
                                <th style={{ width: 170 }}>{t("Status")}</th>
                                <th style={{ width: 190 }}><span className="sr-only">{t("Actions")}</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((r) => (
                                <tr key={r.id} className={highlight === r.id ? "rep-row-new" : ""}>
                                    <td>
                                        <b className="bidi-auto">{r.title}</b>
                                        {r.pinned && <span className="rep-pin" title={t("Pinned")}> ★</span>}
                                        <span className="bkm-sub"><span className="bkm-mono rep-code">{r.code}</span> · {r.language === "fa" ? t("Persian") : t("English")}</span>
                                    </td>
                                    <td>{periodText(r.params)}</td>
                                    <td>
                                        {r.schedule ? t("Schedule “{{name}}”", { name: r.schedule }) : (r.created_by || "—")}
                                        <span className="bkm-sub">{formatWhen(r.created_at)}</span>
                                        {r.delivered_to?.length > 0 && <span className="bkm-sub">{t("Emailed to {{count}} people", { count: r.delivered_to.length })}</span>}
                                    </td>
                                    <td>
                                        {r.files.length ? r.files.map((f) => <span key={f.kind} className="rep-fmt">{f.kind.toUpperCase()}</span>) : "—"}
                                        {r.files.length > 0 && <span className="bkm-sub">{r.files.map((f) => fileSize(f.size)).join(" · ")}{r.page_count ? ` · ${t("{{count}} pages", { count: r.page_count })}` : ""}</span>}
                                    </td>
                                    <td>
                                        <span className={`bkm-pill ${STATUS[r.status]?.pill}`}>{STATUS[r.status]?.label || r.status}</span>
                                        {(r.status === "queued" || r.status === "running") && <div className="rep-prog"><i style={{ width: `${Math.max(r.progress, 15)}%` }} /></div>}
                                        {r.error && <span className="bkm-sub bkm-red">{tb(r.error)}</span>}
                                        {r.omitted?.length > 0 && <span className="bkm-sub">{t("{{count}} sections left out", { count: r.omitted.length })}</span>}
                                        {r.delivery_error && <span className="bkm-sub bkm-orange">{tb(r.delivery_error)}</span>}
                                    </td>
                                    <td>
                                        <div className="alr-row-actions">
                                            {r.status === "ready" && r.files.map((f) => (
                                                <button key={f.kind} type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" disabled={busy === r.id}
                                                        onClick={() => get(r, f.kind)}>{f.kind === "pdf" ? t("PDF") : t("Excel")}</button>
                                            ))}
                                            {r.status === "queued" && canWrite && (
                                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === r.id}
                                                        onClick={() => act(r, () => api.post(`/api/reports/${r.id}/cancel`), t("Could not cancel the report"))}>{t("Cancel")}</button>
                                            )}
                                            {canWrite && !["queued", "running"].includes(r.status) && (
                                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === r.id} title={t("Same settings, today's data; a new report with a new ID")}
                                                        onClick={() => act(r, () => api.post(`/api/reports/${r.id}/rerun`), t("Could not start the report"))}>{t("Build again")}</button>
                                            )}
                                            {canWrite && r.status === "ready" && (
                                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === r.id}
                                                        onClick={() => act(r, () => api.post(`/api/reports/${r.id}/pin`, { pinned: !r.pinned }), t("Could not change the report"))}>
                                                    {r.pinned ? t("Unpin") : t("Pin")}</button>
                                            )}
                                            {canDelete && !["queued", "running"].includes(r.status) && (
                                                <button type="button" className="bkm-btn bkm-btn-sm alr-danger" disabled={busy === r.id}
                                                        onClick={() => setConfirm(r)}>{t("Delete")}</button>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {data && items.length === 0 && (
                                <tr><td colSpan={6}>
                                    <div className="bkm-empty">
                                        <b>{view === "all" && !query ? t("No report has been built yet") : t("No report matches")}</b>
                                        <span>{t("Build one from the report list.")}</span>
                                    </div>
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </section>
            <p className="alr-hint">{t("“Build again” runs the same settings on today's data and makes a new report with a new ID; the earlier file is kept.")}</p>

            {confirm && (
                <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="rep-del-title">
                    <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => setConfirm(null)} />
                    <div className="alr-modal">
                        <h2 id="rep-del-title">{t("Delete this report?")}</h2>
                        <p><b className="bidi-auto">{confirm.title}</b> · <span className="bkm-mono">{confirm.code}</span></p>
                        <p className="bkm-muted">{t("Its files are deleted too, and a copy handed out earlier can no longer be checked against the archive.")}</p>
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={() => setConfirm(null)}>{t("Cancel")}</button>
                            <button type="button" className="bkm-btn alr-danger" onClick={() => {
                                const r = confirm;
                                setConfirm(null);
                                act(r, () => api.delete(`/api/reports/${r.id}`), t("Could not delete the report"));
                            }}>{t("Delete")}</button>
                        </div>
                    </div>
                </div>
            )}
            {verifying && <VerifyModal onClose={() => setVerifying(false)} />}
        </div>
    );
}

/** Is this file exactly one NGCorion built? Compares its SHA-256 with the archive. */
function VerifyModal({ onClose }) {
    const [result, setResult] = useState(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [over, setOver] = useState(false);
    const input = useRef(null);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);

    const check = (file) => {
        if (!file) return;
        setBusy(true);
        setError(null);
        setResult(null);
        const body = new FormData();
        body.append("file", file);
        api.post("/api/reports/verify", body)
            .then(({ data }) => setResult({ ...data, name: file.name }))
            .catch((e) => setError(errorText(e, t("Could not check the file"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="rep-verify-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal">
                <h2 id="rep-verify-title">{t("Check a report file")}</h2>
                <p className="bkm-muted">{t("Choose a PDF or Excel file to see whether it is exactly a report this system built. Any change to the file, even one character, makes the check fail.")}</p>
                <label className={`rep-drop ${over ? "is-over" : ""}`}
                       onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
                       onDrop={(e) => { e.preventDefault(); setOver(false); check(e.dataTransfer.files[0]); }}>
                    <input ref={input} type="file" accept=".pdf,.xlsx" className="sr-only" onChange={(e) => check(e.target.files[0])} />
                    {busy ? t("Checking…") : t("Drop the file here or click to choose it")}
                </label>
                {result && (result.match ? (
                    <div className="rep-verdict ok" role="status">
                        <b>{t("Authentic: this file was built by NGCorion and has not changed.")}</b>
                        <div>{result.title} · <span className="bkm-mono">{result.code}</span> · {formatDateTime(result.created_at)}{result.created_by ? ` · ${result.created_by}` : ""}</div>
                        <div className="rep-hash">SHA-256 {result.sha256}</div>
                    </div>
                ) : (
                    <div className="rep-verdict bad" role="status">
                        <b>{t("Not found: no report in the archive has exactly this content.")}</b>
                        <div>{t("The file was changed after it was built, or it was not built here, or it was deleted from the archive.")}</div>
                    </div>
                ))}
                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot"><button type="button" className="bkm-btn" onClick={onClose}>{t("Close")}</button></div>
            </div>
        </div>
    );
}
