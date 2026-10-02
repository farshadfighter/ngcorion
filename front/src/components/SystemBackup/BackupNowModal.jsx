import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { PARTS, PART_ORDER, backupTable, bytes, destinationLabel, errorText, DEST_TYPE } from "./format.js";

const STAGES = ["prepare", "tables", "files", "encrypt", "verify", "send"];

function stageOf(step) {
    if (!step) return null;
    if (step.startsWith("tables") || step === "database") return "tables";
    if (step.startsWith("send")) return "send";
    return step;
}

/** "Back up now": pick the parts and destinations, then watch it being written. */
export function BackupNowModal({ overview, dests, onClose }) {
    const est = overview?.estimates || {};
    const enabled = dests.filter((d) => d.enabled);
    const [parts, setParts] = useState(["essential", "reports"]);
    const [targets, setTargets] = useState(enabled.map((d) => d.id));
    const [note, setNote] = useState("");
    const [backup, setBackup] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose(Boolean(backup));
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose, backup]);

    // A backup is "ready" once written; copies to the destinations follow (step "send …").
    const pending = backup && (backup.status === "queued" || backup.status === "running" || Boolean(backup.step));
    useEffect(() => {
        if (!pending) return undefined;
        const timer = setInterval(() => {
            api.get(`/api/system-backup/backups/${backup.id}`).then(({ data }) => setBackup(data)).catch(() => {});
        }, 1200);
        return () => clearInterval(timer);
    }, [pending, backup?.id]);

    const toggle = (list, set, v) => set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
    const estimate = parts.reduce((sum, p) => sum + (est[p] || 0), 0) + (est.files || 0);

    const start = () => {
        setBusy(true);
        setError(null);
        api.post("/api/system-backup/backups", { contents: parts, destination_ids: targets, note: note.trim() || null })
            .then(({ data }) => setBackup(data))
            .catch((e) => setError(errorText(e, t("Could not start the backup"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="sbk-now-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => onClose(Boolean(backup))} />
            <div className="alr-modal sbk-modal">
                <h2 id="sbk-now-title">{backup ? t("Making the backup") : t("Back up now")}</h2>
                {!backup ? (
                    <>
                        <p className="bkm-muted">{t("Before an upgrade or a big change. It is made in the background and the program keeps working meanwhile.")}</p>
                        <div className="alr-lbl">{t("Contents")}</div>
                        <div className="sbk-parts">
                            {PART_ORDER.map((p) => {
                                const locked = p === "essential";
                                const on = parts.includes(p);
                                return (
                                    <label key={p} className={`sbk-part ${on ? "is-on" : ""} ${locked ? "is-locked" : ""}`}>
                                        <input type="checkbox" checked={on} disabled={locked} onChange={() => toggle(parts, setParts, p)} />
                                        <div><b>{PARTS[p].label}</b><small>{PARTS[p].hint}</small></div>
                                        <span className="sbk-size">{est[p] != null ? bytes(est[p]) : ""}</span>
                                    </label>
                                );
                            })}
                            <label className="sbk-part is-on is-locked">
                                <input type="checkbox" checked disabled />
                                <div><b>{t("System files")}</b><small>{t("HTTPS certificate, SSH host keys of devices (known_hosts)")}</small></div>
                                <span className="sbk-size">{est.files != null ? bytes(est.files) : ""}</span>
                            </label>
                            <label className="sbk-part is-on is-locked">
                                <input type="checkbox" checked disabled />
                                <div><b>{t("Data encryption key")}</b><small>{t("To open stored passwords (SNMP, SMTP, scheduled jobs) on a new server. Only the backup passphrase opens it.")}</small></div>
                                <span className="sbk-size">—</span>
                            </label>
                        </div>
                        <div className="alr-lbl">{t("Destination")}</div>
                        <div className="sbk-pick">
                            <button type="button" aria-pressed="true" disabled>{t("Server")}</button>
                            {enabled.map((d) => (
                                <button key={d.id} type="button" aria-pressed={targets.includes(d.id)}
                                        onClick={() => toggle(targets, setTargets, d.id)}>
                                    {DEST_TYPE[d.type]} · <span className="bidi-auto">{d.name}</span>
                                </button>
                            ))}
                        </div>
                        {enabled.length === 0 && <p className="alr-hint">{t("No destination outside this server yet. Add one under Destinations.")}</p>}
                        <label className="alr-lbl">
                            {t("Note (optional)")}
                            <input className="sbk-input" value={note} maxLength={300} onChange={(e) => setNote(e.target.value)}
                                   placeholder={t("Before upgrading to the next version")} />
                        </label>
                        {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={() => onClose(false)}>{t("Cancel")}</button>
                            <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy} onClick={start}>
                                {t("Start backup · up to {{size}}", { size: bytes(estimate) })}
                            </button>
                        </div>
                    </>
                ) : (
                    <Progress backup={backup} dests={dests} overview={overview} onClose={() => onClose(true)} />
                )}
            </div>
        </div>
    );
}

function Progress({ backup: b, dests, overview, onClose }) {
    const stage = b.status === "ready" && !b.step ? "done" : stageOf(b.step);
    const at = stage === "done" ? STAGES.length : Math.max(0, STAGES.indexOf(stage));
    const cls = (key) => {
        const i = STAGES.indexOf(key);
        if (b.status === "failed") return i < at ? "done" : i === at ? "failed" : "";
        return i < at ? "done" : i === at ? "running" : "";
    };
    const table = backupTable(b.step);
    const sent = (b.destinations || []);
    const targets = (b.targets ?? dests.filter((d) => d.enabled).map((d) => d.id))
        .map((id) => dests.find((d) => d.id === id)).filter(Boolean);
    return (
        <>
            <div className="sbk-bar" aria-hidden="true"><i style={{ width: `${b.status === "ready" ? 100 : Math.max(b.progress, 4)}%` }} /></div>
            <ul className="sbk-steps">
                <li className={cls("prepare") || "done"}>
                    {t("Checking free space: {{free}} free", { free: bytes(overview?.disk?.free) })}
                </li>
                <li className={cls("prepare") || "done"}>
                    {t("Recording program and database version")} <small dir="ltr">({overview?.app_version} · {overview?.db_revision})</small>
                </li>
                <li className={cls("tables")}>
                    {table ? t("Exporting tables: {{done}} of {{total}}", { done: n(table.done), total: n(table.total) }) : t("Exporting tables")}
                    {table && <small> · <span className="bkm-mono" dir="ltr">{table.table}</span> · {t("{{count}} rows", { count: table.rows })}</small>}
                </li>
                <li className={cls("files")}>{t("System files and encryption key")}</li>
                <li className={cls("encrypt")}>{t("Compressing and encrypting (AES-256-GCM)")}</li>
                <li className={cls("verify")}>{t("Checking: reopening the file and comparing hashes")}</li>
                {targets.map((d) => {
                    const r = sent.find((x) => x.id === d.id);
                    const c = r ? (r.status === "ok" ? "done" : "failed") : (stage === "send" ? "running" : "");
                    return (
                        <li key={d.id} className={c}>
                            {t("Sending to {{name}}", { name: d.name })}
                            {r?.status === "failed" && <small> · {tb(r.error || "")}</small>}
                            {!r && stage !== "send" && <small> · <span dir="ltr">{destinationLabel(d)}</span></small>}
                        </li>
                    );
                })}
            </ul>
            {b.status === "failed" && <div className="bkm-note bkm-note-error" role="alert">{tb(b.error || "")}</div>}
            {b.status === "ready" && !b.step && (
                <div className={`bkm-note ${b.verify_status === "ok" ? "bkm-note-ok" : "bkm-note-orange"}`} role="status">
                    {b.verify_status === "ok"
                        ? t("The backup is ready and checked: {{size}}.", { size: bytes(b.size_bytes) })
                        : t("The backup was written but its check failed: {{error}}", { error: b.verify_error || "" })}
                </div>
            )}
            <p className="alr-hint">{t("The export is taken from a snapshot of the database: work running at the same time (audits, monitoring) carries on, and the whole backup belongs to one moment.")}</p>
            <div className="alr-modal-foot">
                <button type="button" className="bkm-btn" onClick={onClose}>
                    {b.status === "queued" || b.status === "running" || b.step ? t("Continue in the background") : t("Close")}
                </button>
            </div>
        </>
    );
}
