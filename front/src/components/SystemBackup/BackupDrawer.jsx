import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { duration, formatDateTime } from "../../utils/dates.js";
import { DestChips, Health } from "./parts.jsx";
import { KIND, PARTS, TIER, bytes, contentsText, downloadBackup, errorText } from "./format.js";

/** One backup: what is in it, where copies went, checks, and what can be done with it. */
export function BackupDrawer({ backup: b, dests, onClose, onChanged, onRestore }) {
    const [busy, setBusy] = useState(null);
    const [error, setError] = useState(null);
    const [note, setNote] = useState(null);
    const [passphrase, setPassphrase] = useState("");
    const [askPass, setAskPass] = useState(false);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose(false);
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);

    const run = (key, fn, ok) => {
        setBusy(key);
        setError(null);
        setNote(null);
        fn().then(() => { if (ok) setNote(ok); onChanged(); })
            .catch((e) => {
                const d = e?.response?.status === 422 && e?.response?.data?.detail;
                if (d && /passphrase/i.test(d)) setAskPass(true);
                setError(errorText(e, t("The request failed")));
            })
            .finally(() => setBusy(null));
    };
    const body = () => ({ passphrase: passphrase || null });
    const verify = () => run("verify", () => api.post(`/api/system-backup/backups/${b.id}/verify`, body()));
    const test = () => run("test", () => api.post(`/api/system-backup/backups/${b.id}/test`, body()),
        t("The restore test started. Its result appears under “Restores and tests”."));
    const resend = () => run("resend", () => api.post(`/api/system-backup/backups/${b.id}/resend`, {}));
    const remove = () => {
        const copies = (b.destinations || []).filter((d) => d.status === "ok").length;
        const msg = copies
            ? t("Delete this backup from the server and its {{count}} copies on the destinations?", { count: copies })
            : t("Delete this backup from the server?");
        if (!window.confirm(msg)) return;
        run("delete", () => api.delete(`/api/system-backup/backups/${b.id}`).then(() => onClose(true)));
    };
    const ready = b.status === "ready";
    const rows = b.summary?.rows_by_part || {};

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="sbk-drawer-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => onClose(false)} />
            <aside className="bkm-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="sbk-drawer-title">{formatDateTime(b.created_at)}</h2>
                        <div className="bkm-row-gap" style={{ marginTop: 6 }}>
                            <span className={`bkm-pill ${KIND[b.kind]?.pill}`}>{KIND[b.kind]?.label}</span>
                            {b.tier && <span className="bkm-pill bkm-pill-muted">{TIER[b.tier]}</span>}
                        </div>
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label={t("Close")} onClick={() => onClose(false)}>×</button>
                </header>
                <div className="bkm-drawer-body">
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                    {note && <div className="bkm-note bkm-note-ok" role="status">{note}</div>}
                    <section>
                        <div className="bkm-kv"><span>{t("File")}</span><b className="bkm-mono" dir="ltr">{b.filename || "—"}</b></div>
                        <div className="bkm-kv"><span>{t("Size")}</span><b>{bytes(b.size_bytes)}</b></div>
                        <div className="bkm-kv"><span>{t("Contents")}</span><b>{contentsText(b.contents)}</b></div>
                        <div className="bkm-kv"><span>{t("Program version")}</span><b dir="ltr">{b.app_version || "—"}</b></div>
                        <div className="bkm-kv"><span>{t("Database version")}</span><b className="bkm-mono" dir="ltr">{b.db_revision || "—"}</b></div>
                        {b.source_host && <div className="bkm-kv"><span>{t("Source server")}</span><b dir="ltr">{b.source_host}</b></div>}
                        <div className="bkm-kv"><span>{t("Took")}</span><b>{Date.parse(b.finished_at) - Date.parse(b.started_at) < 1000 ? t("Under a second") : duration(b.started_at, b.finished_at) || "—"}</b></div>
                        {b.created_by && <div className="bkm-kv"><span>{t("By")}</span><b>{b.created_by}</b></div>}
                        {b.note && b.kind !== "safety" && <div className="bkm-kv"><span>{t("Note")}</span><b className="bidi-auto">{tb(b.note)}</b></div>}
                        {b.sha256 && <div className="bkm-kv"><span>SHA-256</span><b className="bkm-mono" dir="ltr" style={{ fontSize: 11, overflowWrap: "anywhere" }}>{b.sha256}</b></div>}
                    </section>
                    {b.summary?.tables != null && (
                        <section>
                            <h3 className="bkm-h3">{t("Inside")}</h3>
                            <div className="bkm-kv"><span>{t("Tables")}</span><b>{n(b.summary.tables)}</b></div>
                            {Object.entries(rows).map(([part, count]) => (
                                <div key={part} className="bkm-kv"><span>{PARTS[part]?.label || part}</span><b>{t("{{count}} rows", { count })}</b></div>
                            ))}
                            <div className="bkm-kv"><span>{t("System files")}</span><b>{n(b.summary.files || 0)}</b></div>
                        </section>
                    )}
                    <section>
                        <h3 className="bkm-h3">{t("Copies")}</h3>
                        <DestChips b={b} dests={dests} />
                    </section>
                    <section>
                        <h3 className="bkm-h3">{t("Health")}</h3>
                        <Health b={b} />
                        {b.verified_at && <span className="bkm-sub">{t("Checked {{when}}", { when: formatDateTime(b.verified_at) })}</span>}
                        {b.tested_at && <span className="bkm-sub">{t("Restore-tested {{when}}", { when: formatDateTime(b.tested_at) })}</span>}
                    </section>
                    {askPass && (
                        <label className="alr-lbl">
                            {t("Passphrase of this backup")}
                            <input type="password" className="sbk-input" value={passphrase} autoComplete="off"
                                   onChange={(e) => setPassphrase(e.target.value)} />
                            <small className="alr-hint">{t("This backup was made with another passphrase (another server, or before the passphrase changed).")}</small>
                        </label>
                    )}
                    {b.error && <div className="bkm-note bkm-note-error">{tb(b.error)}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <div className="bkm-row-gap">
                        {ready && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => onRestore(b)}>{t("Restore…")}</button>}
                        {ready && (
                            <button type="button" className="bkm-btn" disabled={!!busy}
                                    onClick={() => { setBusy("download"); downloadBackup(b).catch(() => setError(t("Could not download the file"))).finally(() => setBusy(null)); }}>
                                {t("Download")}
                            </button>
                        )}
                        {ready && <button type="button" className="bkm-btn" disabled={!!busy} onClick={verify}>{busy === "verify" ? t("Checking…") : t("Check now")}</button>}
                        {ready && <button type="button" className="bkm-btn" disabled={!!busy} onClick={test}>{t("Test restore")}</button>}
                        {ready && dests.some((d) => d.enabled) && <button type="button" className="bkm-btn" disabled={!!busy} onClick={resend}>{busy === "resend" ? t("Sending…") : t("Send to destinations")}</button>}
                    </div>
                    {b.status !== "queued" && b.status !== "running" && (
                        <button type="button" className="bkm-btn alr-danger" disabled={!!busy} onClick={remove}>{t("Delete")}</button>
                    )}
                </footer>
            </aside>
        </div>
    );
}
