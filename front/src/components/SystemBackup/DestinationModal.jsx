import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { errorText } from "./format.js";

const EMPTY = { name: "", type: "sftp", host: "", port: "", username: "", domain: "", share: "", path: "", auth: "password", secret: "", enabled: true };

/** Add or edit an SFTP server or Windows share; saving tests the connection. */
export function DestinationModal({ dest, onClose }) {
    const [form, setForm] = useState(() => (dest ? { ...EMPTY, ...dest, port: dest.port || "", secret: "" } : EMPTY));
    const [state, setState] = useState(null);
    const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e?.target ? (e.target.type === "checkbox" ? e.target.checked : e.target.value) : e }));

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose(Boolean(state?.saved));
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose, state]);

    const smb = form.type === "smb";
    const valid = form.name.trim() && form.host.trim() && (!smb || form.share.trim()) && (dest?.has_secret || form.secret || smb);
    const save = (e) => {
        e.preventDefault();
        setState({ busy: true });
        const body = { ...form, port: form.port ? Number(form.port) : null, secret: form.secret || null };
        const req = dest ? api.put(`/api/system-backup/destinations/${dest.id}`, body) : api.post("/api/system-backup/destinations", body);
        req.then(({ data }) => api.post(`/api/system-backup/destinations/${data.id}/test`))
            .then(({ data }) => setState({ saved: true, test: data }))
            .catch((err) => setState({ error: errorText(err, t("Could not save the destination")) }));
    };

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="sbk-dest-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => onClose(Boolean(state?.saved))} />
            <div className="alr-modal sbk-modal">
                <h2 id="sbk-dest-title">{dest ? t("Edit destination") : t("Add destination")}</h2>
                {state?.saved ? (
                    <>
                        {state.test.ok ? (
                            <div className="bkm-note bkm-note-ok" role="status">
                                {t("Saved. Connected and wrote a test file.")}
                                {state.test.fingerprint && <div>{t("Host key pinned:")} <span className="bkm-mono" dir="ltr">{state.test.fingerprint}</span></div>}
                            </div>
                        ) : (
                            <div className="bkm-note bkm-note-orange" role="status">
                                {t("Saved, but the connection test failed:")} {tb(state.test.error || "")}
                            </div>
                        )}
                        <div className="alr-modal-foot"><button type="button" className="bkm-btn bkm-btn-primary" onClick={() => onClose(true)}>{t("Close")}</button></div>
                    </>
                ) : (
                    <form onSubmit={save} className="rep-stack">
                        <div className="rep-seg" role="group" aria-label={t("Type")}>
                            <button type="button" aria-pressed={!smb} onClick={() => set("type")("sftp")}>SFTP</button>
                            <button type="button" aria-pressed={smb} onClick={() => set("type")("smb")}>{t("Windows share (SMB)")}</button>
                        </div>
                        <label className="alr-lbl">{t("Name")}
                            <input className="sbk-input" value={form.name} onChange={set("name")} maxLength={120} placeholder={smb ? t("File server") : t("Backup server")} />
                        </label>
                        <div className="sbk-row">
                            <label className="alr-lbl">{t("Server")}
                                <input className="sbk-input" dir="ltr" value={form.host} onChange={set("host")} placeholder={smb ? "fs01.company.local" : "backup01.company.local"} />
                            </label>
                            <label className="alr-lbl">{t("Port")}
                                <input className="sbk-input" dir="ltr" type="number" min="1" max="65535" value={form.port} onChange={set("port")} placeholder={smb ? "445" : "22"} />
                            </label>
                        </div>
                        {smb && (
                            <div className="sbk-row">
                                <label className="alr-lbl">{t("Share")}
                                    <input className="sbk-input" dir="ltr" value={form.share} onChange={set("share")} placeholder="backups" />
                                </label>
                                <label className="alr-lbl">{t("Domain (optional)")}
                                    <input className="sbk-input" dir="ltr" value={form.domain} onChange={set("domain")} placeholder="COMPANY" />
                                </label>
                            </div>
                        )}
                        <label className="alr-lbl">{t("Folder")}
                            <input className="sbk-input" dir="ltr" value={form.path} onChange={set("path")} placeholder={smb ? "ngcorion" : "/srv/backups/ngcorion"} />
                            <small className="alr-hint">{t("Created if it does not exist.")}</small>
                        </label>
                        <label className="alr-lbl">{t("Username")}
                            <input className="sbk-input" dir="ltr" value={form.username} onChange={set("username")} autoComplete="off" />
                        </label>
                        {!smb && (
                            <div className="rep-seg" role="group" aria-label={t("Sign-in")}>
                                <button type="button" aria-pressed={form.auth === "password"} onClick={() => set("auth")("password")}>{t("Password")}</button>
                                <button type="button" aria-pressed={form.auth === "key"} onClick={() => set("auth")("key")}>{t("SSH key")}</button>
                            </div>
                        )}
                        <label className="alr-lbl">
                            {!smb && form.auth === "key" ? t("Private key (OpenSSH or PEM, without a passphrase)") : t("Password")}
                            {!smb && form.auth === "key" ? (
                                <textarea className="sbk-input" dir="ltr" value={form.secret} onChange={set("secret")}
                                          placeholder={dest?.has_secret ? t("Unchanged") : "-----BEGIN OPENSSH PRIVATE KEY-----"} />
                            ) : (
                                <input className="sbk-input" type="password" value={form.secret} onChange={set("secret")} autoComplete="new-password"
                                       placeholder={dest?.has_secret ? t("Unchanged") : ""} />
                            )}
                            <small className="alr-hint">{t("Stored encrypted. Give this account write access to the folder only.")}</small>
                        </label>
                        {!smb && <p className="alr-hint">{t("The server's host key is pinned on the first connection, like device SSH: if it changes later, copies are refused until you clear the pin.")}</p>}
                        {state?.error && <div className="bkm-note bkm-note-error" role="alert">{state.error}</div>}
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={() => onClose(false)}>{t("Cancel")}</button>
                            <button type="submit" className="bkm-btn bkm-btn-primary" disabled={!valid || state?.busy}>
                                {state?.busy ? t("Saving and testing…") : t("Save and test")}
                            </button>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
}
