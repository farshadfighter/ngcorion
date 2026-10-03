import { useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { errorText, platformOf } from "./softwareFormat.js";

/**
 * Read an asset's installed software now, without a full audit. The
 * username and password are sent once and never stored.
 */
export function CollectForm({ asset, onDone, onCancel, compact = false }) {
    const [platform, setPlatform] = useState(platformOf(asset));
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [port, setPort] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const first = useRef(null);

    useEffect(() => { first.current?.focus(); }, []);

    const submit = (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        api.post(`/api/software/assets/${asset.id}/collect`, {
            platform, username: username.trim(), password, port: port ? Number(port) : null,
        }, { timeout: 180000 })
            .then(({ data }) => { setPassword(""); onDone?.(data.collection); })
            .catch((err) => setError(errorText(err, t("Could not collect the software list"))))
            .finally(() => setBusy(false));
    };

    return (
        <form className={`sw-collect ${compact ? "is-compact" : ""}`} onSubmit={submit} autoComplete="off">
            <div className="sw-seg" role="radiogroup" aria-label={t("Platform")}>
                {[["linux", t("Linux · SSH")], ["windows", t("Windows · WinRM")]].map(([value, label]) => (
                    <button key={value} type="button" role="radio" aria-checked={platform === value}
                            className={platform === value ? "is-on" : ""} onClick={() => setPlatform(value)}>{label}</button>
                ))}
            </div>
            <div className="sw-collect-grid">
                <label className="alr-lbl">{platform === "linux" ? t("SSH username") : t("Windows username")}
                    <input ref={first} className="bkm-select sw-ltr" value={username} maxLength={200} autoComplete="off"
                           onChange={(e) => setUsername(e.target.value)} placeholder={platform === "linux" ? "auditor" : "DOMAIN\\auditor"} />
                </label>
                <label className="alr-lbl">{t("Password")}
                    <input type="password" className="bkm-select sw-ltr" value={password} maxLength={500} autoComplete="new-password"
                           onChange={(e) => setPassword(e.target.value)} />
                </label>
                <label className="alr-lbl sw-port">{t("Port")}
                    <input className="bkm-select sw-ltr" inputMode="numeric" value={port} maxLength={5}
                           onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))}
                           placeholder={platform === "linux" ? n(22) : n(5985)} />
                </label>
            </div>
            <p className="alr-hint">
                {platform === "linux"
                    ? t("Reads the package list with dpkg or rpm - no sudo, nothing is changed. Takes a few seconds.")
                    : t("Reads the installed programs and updates from the registry - nothing is changed. Takes a few seconds.")}
                {" "}{t("The username and password are used for this collection only and are not stored.")}
            </p>
            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
            <div className="sw-collect-actions">
                <button type="submit" className="bkm-btn bkm-btn-primary" disabled={busy || !username.trim() || !password}>
                    {busy ? t("Collecting…") : t("Collect")}
                </button>
                {onCancel && <button type="button" className="bkm-btn" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>}
            </div>
        </form>
    );
}
