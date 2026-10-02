import { useCallback, useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDateTime, formatWhen } from "../../utils/dates.js";
import { KIND, PARTS, RESTORE_STEPS, bytes, contentsText, errorText } from "./format.js";

const WIZARD = [t("Choose a backup"), t("Check and passphrase"), t("Confirm"), t("Restore"), t("Result")];
const ORDER = ["validate", "maintenance", "safety", "staging", "load", "check", "upgrade", "carry", "rekey", "swap", "files", "finish"];
const CARRIED = {
    cve_entries: PARTS.cve.label, cve_cpe_matches: PARTS.cve.label,
    asset_metric_samples: PARTS.noc_history.label, asset_metric_rollups: PARTS.noc_history.label,
    report_files: PARTS.reports.label, backup_destinations: t("Backup destinations"),
};
const HIGHLIGHTS = [
    ["assets", t("Assets")], ["audit_sessions", t("Audit sessions")], ["device_backups", t("Device backups")],
    ["users", t("Users")], ["remediation_items", t("Remediation findings")], ["reports", t("Reports")],
    ["alerts", t("Alerts")], ["logs", t("Log entries")],
];

/** Plain fetch for the restore's own polling: during maintenance and right after
 *  the swap the shared client's 401/403 handling (logout, permission banner) must
 *  not fire. */
async function poll(path) {
    const token = localStorage.getItem("token");
    const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    let body = null;
    try { body = await res.json(); } catch { /* not JSON */ }
    return { status: res.status, body };
}

/** Restore a backup onto this server: choose, check, confirm, watch, result. */
export function RestoreWizard({ backup: initial, backups, onClose }) {
    const [step, setStep] = useState(initial ? 1 : 0);
    const [backup, setBackup] = useState(initial || null);
    const [restore, setRestore] = useState(null);
    const running = step === 3;
    const finished = useCallback((r) => { setRestore(r); setStep(4); }, []);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && !running && onClose(step >= 3);
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose, running, step]);

    // While this wizard shows the restore, the app-wide maintenance overlay stays out of the way.
    useEffect(() => {
        document.body.dataset.restoreWizard = "1";
        return () => { delete document.body.dataset.restoreWizard; };
    }, []);

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="sbk-restore-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => !running && onClose(step >= 3)} />
            <div className="alr-modal sbk-modal is-wide">
                <h2 id="sbk-restore-title">{t("Restore NGCorion from a backup")}</h2>
                <div className="sbk-wizard-steps" aria-hidden="true">
                    {WIZARD.map((label, i) => (
                        <span key={label} className={i < step ? "done" : i === step ? "now" : ""}>{n(i + 1)}. {label}</span>
                    ))}
                </div>
                {step === 0 && <Choose backups={backups} onPick={(b) => { setBackup(b); setStep(1); }} onCancel={() => onClose(false)} />}
                {step === 1 && backup && (
                    <Check backup={backup} onBack={initial ? null : () => setStep(0)} onCancel={() => onClose(false)}
                           onNext={(ctx) => { setBackup({ ...backup, ...ctx }); setStep(2); }} />
                )}
                {step === 2 && backup && (
                    <Confirm backup={backup} onBack={() => setStep(1)} onCancel={() => onClose(false)}
                             onStarted={(r) => { setRestore(r); setStep(3); }} />
                )}
                {step === 3 && restore && <Watch restore={restore} onDone={finished} />}
                {step === 4 && restore && <Result restore={restore} backup={backup} onClose={() => onClose(true)} />}
            </div>
        </div>
    );
}

// ── 1. choose ─────────────────────────────────────────────────────────────

function Choose({ backups, onPick, onCancel }) {
    const ready = backups.filter((b) => b.status === "ready");
    const [picked, setPicked] = useState(ready[0]?.id || null);
    const [upload, setUpload] = useState(null);
    const input = useRef(null);

    const send = (file) => {
        if (!file) return;
        setUpload({ name: file.name, pct: 0 });
        api.post("/api/system-backup/upload", file, {
            headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(file.name) },
            onUploadProgress: (e) => e.total && setUpload({ name: file.name, pct: Math.round((e.loaded / e.total) * 100) }),
        }).then(({ data }) => onPick(data))
            .catch((e) => setUpload({ name: file.name, error: errorText(e, t("Could not upload the file")) }));
    };

    return (
        <>
            <div className="sbk-wizard">
                <section className="rep-stack">
                    <div className="alr-lbl">{t("A backup on this server")}</div>
                    {ready.length === 0 && <p className="alr-hint">{t("No backup on this server yet.")}</p>}
                    <div className="sbk-parts" style={{ maxHeight: 360, overflowY: "auto" }}>
                        {ready.map((b) => (
                            <label key={b.id} className={`sbk-part ${picked === b.id ? "is-on" : ""}`}>
                                <input type="radio" name="sbk-pick" checked={picked === b.id} onChange={() => setPicked(b.id)} />
                                <div>
                                    <b>{formatWhen(b.created_at)} · {KIND[b.kind]?.label}</b>
                                    <small>{contentsText(b.contents)}{b.note ? ` · ${b.note}` : ""}</small>
                                </div>
                                <span className="sbk-size">{bytes(b.size_bytes)}</span>
                            </label>
                        ))}
                    </div>
                </section>
                <section className="rep-stack">
                    <div className="alr-lbl">{t("Or a backup file")}</div>
                    <label className="rep-drop" onDragOver={(e) => e.preventDefault()}
                           onDrop={(e) => { e.preventDefault(); send(e.dataTransfer.files[0]); }}>
                        <input ref={input} type="file" accept=".ngbak" className="sr-only" onChange={(e) => send(e.target.files[0])} />
                        {upload && !upload.error
                            ? t("Uploading {{name}}: {{pct}}%", { name: upload.name, pct: n(upload.pct) })
                            : t("Drop a .ngbak file here or click to choose it")}
                    </label>
                    {upload && !upload.error && <div className="sbk-bar"><i style={{ width: `${upload.pct}%` }} /></div>}
                    {upload?.error && <div className="bkm-note bkm-note-error" role="alert">{upload.error}</div>}
                    <p className="alr-hint">{t("From another server or an older copy. The file is kept in the backup list after upload.")}</p>
                </section>
            </div>
            <div className="alr-modal-foot">
                <button type="button" className="bkm-btn" onClick={onCancel}>{t("Cancel")}</button>
                <button type="button" className="bkm-btn bkm-btn-primary" disabled={!picked || (upload && !upload.error)}
                        onClick={() => onPick(ready.find((b) => b.id === picked))}>{t("Next")}</button>
            </div>
        </>
    );
}

// ── 2. check ──────────────────────────────────────────────────────────────

function Check({ backup, onBack, onCancel, onNext }) {
    const [passphrase, setPassphrase] = useState("");
    const [info, setInfo] = useState(null);
    const [health, setHealth] = useState(null);       // null | "checking" | {ok, error}
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(true);

    // Only callbacks set state here, so the first run can start from an effect.
    const fetchInfo = useCallback((pass) => api.post(`/api/system-backup/backups/${backup.id}/inspect`, { passphrase: pass || null })
        .then(({ data }) => {
            setInfo(data);
            if (data.needs_passphrase || !data.compatibility?.ok) return undefined;
            setHealth("checking");
            return api.post(`/api/system-backup/backups/${backup.id}/verify`, { passphrase: pass || null })
                .then(({ data: v }) => setHealth({ ok: v.verify_status === "ok", error: v.verify_error }))
                .catch((e) => setHealth({ ok: false, error: errorText(e, t("The check failed")) }));
        })
        .catch((e) => setError(errorText(e, t("Could not open the backup"))))
        .finally(() => setBusy(false)), [backup.id]);
    const load = (pass) => {
        setBusy(true);
        setError(null);
        fetchInfo(pass);
    };

    useEffect(() => { fetchInfo(null); }, [fetchInfo]);

    const compat = info?.compatibility;
    const sameVersion = compat?.same_version;
    const missing = ["cve", "noc_history", "reports"].filter((p) => !(info?.contents || backup.contents || []).includes(p));
    const canGo = info && !info.needs_passphrase && compat?.ok && health?.ok;

    return (
        <>
            <div className="sbk-wizard">
                <section className="rep-stack">
                    <h3 className="bkm-h3">{t("Selected backup")}</h3>
                    <dl className="sbk-facts">
                        <dt>{t("Made")}</dt><dd>{formatDateTime(info?.created_at || backup.created_at)} · {KIND[backup.kind]?.label}</dd>
                        <dt>{t("Program version")}</dt>
                        <dd><span dir="ltr">{info?.app_version || backup.app_version || "—"}</span>{compat?.ok && ` · ${sameVersion ? t("same version") : t("older: upgraded during the restore")}`}</dd>
                        <dt>{t("Database version")}</dt><dd className="bkm-mono" dir="ltr">{info?.db_revision || backup.db_revision || "—"}</dd>
                        <dt>{t("Source server")}</dt>
                        <dd><span dir="ltr">{info?.source_host || backup.source_host || "—"}</span>{info?.same_server ? ` (${t("this server")})` : ""}</dd>
                        <dt>{t("Contents")}</dt><dd>{contentsText(info?.contents || backup.contents)} · {t("system files, encryption key")}</dd>
                        <dt>{t("Health")}</dt>
                        <dd>
                            {health === "checking" && <span className="bkm-pill bkm-pill-run">{t("Checking every part…")}</span>}
                            {health?.ok && <span className="bkm-pill bkm-pill-ok">{t("Passphrase correct · every part matches its hash")}</span>}
                            {health && health !== "checking" && !health.ok && <span className="bkm-pill bkm-pill-bad">{t("Damaged")}</span>}
                            {!health && "—"}
                        </dd>
                    </dl>
                    {health?.error && <div className="bkm-note bkm-note-error">{tb(health.error)}</div>}
                    {info?.highlights && (
                        <div className="sbk-counts">
                            {HIGHLIGHTS.map(([k, label]) => (
                                <div key={k}><b>{n(info.highlights[k] || 0)}</b><span>{label}</span></div>
                            ))}
                        </div>
                    )}
                </section>
                <section className="rep-stack">
                    {info?.needs_passphrase && (
                        <form className="rep-stack" onSubmit={(e) => { e.preventDefault(); load(passphrase); }}>
                            <div className="bkm-note bkm-note-orange">{t("This backup was made with another passphrase (another server, or before the passphrase changed). Enter that passphrase.")}</div>
                            <label className="alr-lbl">{t("Passphrase of this backup")}
                                <input type="password" className="sbk-input" value={passphrase} autoComplete="off" autoFocus
                                       onChange={(e) => setPassphrase(e.target.value)} />
                            </label>
                            <div><button type="submit" className="bkm-btn bkm-btn-primary" disabled={!passphrase || busy}>{t("Open the backup")}</button></div>
                        </form>
                    )}
                    {compat && !compat.ok && (
                        <div className="bkm-note bkm-note-error" role="alert">
                            {compat.reason === "newer_version"
                                ? t("This backup comes from a newer NGCorion version. Update this server first, then restore it.")
                                : t("This backup does not say which database version it holds, so it cannot be restored.")}
                        </div>
                    )}
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                    {info && !info.needs_passphrase && (
                        <>
                            <h3 className="bkm-h3">{t("What gets replaced")}</h3>
                            <ul className="sbk-legend">
                                <li>{t("All current data is replaced with the data of this backup; anything recorded after {{when}} is lost.", { when: formatDateTime(info.created_at) })}</li>
                                {missing.map((p) => <li key={p}>{t("The current {{part}} is kept, because this backup does not hold it.", { part: PARTS[p].label })}</li>)}
                                <li>{t("The backup list, the backup settings and passphrase, and the destinations of this server are kept.")}</li>
                                <li>{t("The license is not touched (it is bound to this server).")}</li>
                                {!info.same_server && <li>{t("Stored passwords (SNMP, SMTP, scheduled jobs) are re-encrypted for this server with the key inside the backup.")}</li>}
                            </ul>
                        </>
                    )}
                </section>
            </div>
            <div className="alr-modal-foot">
                {onBack && <button type="button" className="bkm-btn" onClick={onBack}>{t("Back")}</button>}
                <button type="button" className="bkm-btn" onClick={onCancel}>{t("Cancel")}</button>
                <button type="button" className="bkm-btn bkm-btn-primary" disabled={!canGo}
                        onClick={() => onNext({ passphrase: passphrase || null, info })}>{t("Next")}</button>
            </div>
        </>
    );
}

// ── 3. confirm ────────────────────────────────────────────────────────────

function Confirm({ backup, onBack, onCancel, onStarted }) {
    const [word, setWord] = useState("");
    const [password, setPassword] = useState("");
    const [state, setState] = useState(null);
    const go = (e) => {
        e.preventDefault();
        setState({ busy: true });
        api.post("/api/system-backup/restores", { backup_id: backup.id, passphrase: backup.passphrase, confirm: word, password })
            .then(({ data }) => onStarted(data))
            .catch((err) => setState({ error: errorText(err, t("Could not start the restore")) }));
    };
    return (
        <form className="sbk-wizard" onSubmit={go}>
            <section className="sbk-danger">
                <h3>{t("Full restore")}</h3>
                <ol>
                    <li>{t("First a “safety backup” of the current state is made, so you can go back if needed.")}</li>
                    <li>{t("The program goes into maintenance for a few minutes; users see a maintenance page.")}</li>
                    <li>{t("Background tasks (monitoring, schedules, reports) pause until the restore ends.")}</li>
                </ol>
                <label className="alr-lbl">
                    <span>{t("To confirm, type")} <b dir="ltr">RESTORE</b></span>
                    <input className="sbk-input" dir="ltr" value={word} onChange={(e) => setWord(e.target.value)} autoComplete="off" autoFocus />
                </label>
                <label className="alr-lbl">{t("Your account password")}
                    <input type="password" className="sbk-input" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
                </label>
                {state?.error && <div className="bkm-note bkm-note-error" role="alert">{state.error}</div>}
                <div className="bkm-row-gap">
                    <button type="submit" className="bkm-btn bkm-btn-danger" disabled={word.trim().toUpperCase() !== "RESTORE" || !password || state?.busy}>
                        {t("Restore")}
                    </button>
                    <button type="button" className="bkm-btn" onClick={onBack}>{t("Back")}</button>
                    <button type="button" className="bkm-btn" onClick={onCancel}>{t("Cancel")}</button>
                </div>
            </section>
            <section className="rep-stack">
                <h3 className="bkm-h3">{t("During the restore")}</h3>
                <ul className="sbk-steps">
                    {ORDER.map((k) => <li key={k}>{RESTORE_STEPS[k]}</li>)}
                </ul>
                <p className="alr-hint">{t("Until the switch to the restored data, the running system is not touched: if any step before it fails, everything stays as it was.")}</p>
            </section>
        </form>
    );
}

// ── 4. watch ──────────────────────────────────────────────────────────────

function Watch({ restore, onDone }) {
    const [state, setState] = useState({ step: restore.step || "validate", progress: restore.progress || 1 });
    useEffect(() => {
        let alive = true;
        let timer;
        const tick = async () => {
            try {
                const m = await poll("/api/system-backup/maintenance");
                if (m.status === 200 && m.body?.maintenance) {
                    if (alive) setState({ step: m.body.maintenance.step, progress: m.body.maintenance.progress || 0 });
                } else {
                    const r = await poll(`/api/system-backup/restores/${restore.id}`);
                    if (r.status === 401) { onDone({ ...restore, status: "succeeded", signedOut: true }); return; }
                    if (r.status === 200 && r.body) {
                        if (r.body.status === "succeeded" || r.body.status === "failed") { onDone(r.body); return; }
                        if (alive) setState({ step: r.body.step, progress: r.body.progress });
                    }
                }
            } catch { /* the server may be busy for a moment */ }
            if (alive) timer = setTimeout(tick, 1500);
        };
        timer = setTimeout(tick, 800);
        return () => { alive = false; clearTimeout(timer); };
    }, [restore, onDone]);

    const at = Math.max(0, ORDER.indexOf(state.step));
    return (
        <div className="rep-stack">
            <div className="sbk-bar" aria-hidden="true"><i style={{ width: `${Math.max(state.progress, 3)}%` }} /></div>
            <ul className="sbk-steps" aria-live="polite">
                {ORDER.map((k, i) => <li key={k} className={i < at ? "done" : i === at ? "running" : ""}>{RESTORE_STEPS[k]}</li>)}
            </ul>
            <p className="alr-hint">{t("Keep this window open. NGCorion is in maintenance mode until the restore ends.")}</p>
        </div>
    );
}

// ── 5. result ─────────────────────────────────────────────────────────────

function Result({ restore: r, backup, onClose }) {
    if (r.status !== "succeeded") {
        const after = (r.error || "").startsWith("The backup was restored");
        return (
            <div className="rep-stack">
                <div className="bkm-note bkm-note-error" role="alert"><b>{t("The restore failed.")}</b> {tb(r.error || "")}</div>
                {!after && <div className="bkm-note">{t("Nothing was changed: the system is exactly as it was before the restore.")}</div>}
                <div className="alr-modal-foot"><button type="button" className="bkm-btn" onClick={onClose}>{t("Close")}</button></div>
            </div>
        );
    }
    const res = r.result || {};
    // Tables kept from the running system, named by what they hold.
    const carried = [...new Set(Object.keys(res.carried || {}).map((k) => CARRIED[k]).filter(Boolean))];
    return (
        <div className="rep-stack">
            <div className="bkm-note bkm-note-ok" role="status">
                <b>{t("NGCorion was restored from the backup of {{when}}.", { when: formatDateTime(backup.info?.created_at || backup.created_at) })}</b>
            </div>
            <ul className="sbk-legend">
                {res.safety_backup && <li>{t("Safety backup of the previous state:")} <span className="bkm-mono" dir="ltr">{res.safety_backup}</span></li>}
                {res.upgraded_from && <li>{t("The database was upgraded from version {{rev}}.", { rev: res.upgraded_from })}</li>}
                {res.secrets && !res.secrets.same_key && <li>{t("{{count}} stored passwords re-encrypted for this server.", { count: res.secrets.rekeyed || 0 })}</li>}
                {carried.length > 0 && <li>{t("Kept from the running system: {{tables}}", { tables: carried.join(t(", ")) })}</li>}
                {res.files > 0 && <li>{t("{{count}} system files restored.", { count: res.files })}</li>}
                {(res.file_errors || []).map((e) => <li key={e} className="bkm-red">{e}</li>)}
            </ul>
            {r.signedOut && <div className="bkm-note bkm-note-orange">{t("Your session belongs to the data before the restore. Sign in again with an account from the restored data.")}</div>}
            <div className="alr-modal-foot">
                <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => { onClose(); window.location.reload(); }}>{t("Reload NGCorion")}</button>
            </div>
        </div>
    );
}
