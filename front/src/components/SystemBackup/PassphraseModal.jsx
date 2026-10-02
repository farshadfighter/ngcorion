import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { errorText } from "./format.js";

const MIN = 12;

/** A rough strength gauge: length and variety of characters. */
function strength(p) {
    if (!p) return 0;
    let classes = 0;
    if (/[a-z]/.test(p)) classes++;
    if (/[A-Z]/.test(p)) classes++;
    if (/\d/.test(p)) classes++;
    if (/[^A-Za-z0-9]/.test(p)) classes++;
    const score = Math.min(4, Math.floor(p.length / 6) + classes - 1);
    return p.length < MIN ? Math.min(score, 1) : Math.max(score, 2);
}
const LEVELS = [["", "#e5e7eb"], [t("Too short"), "#dc2626"], [t("Fair"), "#d97706"], [t("Good"), "#16a34a"], [t("Strong"), "#15803d"]];

/** Set, change or test the backup passphrase. */
export function PassphraseModal({ mode, onClose }) {
    const [current, setCurrent] = useState("");
    const [next, setNext] = useState("");
    const [again, setAgain] = useState("");
    const [check, setCheck] = useState("");
    const [state, setState] = useState(null);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose(false);
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);

    if (mode === "check") {
        const test = (e) => {
            e.preventDefault();
            setState({ busy: true });
            api.post("/api/system-backup/passphrase/check", { passphrase: check })
                .then(({ data }) => setState({ result: data.ok }))
                .catch((err) => setState({ error: errorText(err, t("The check failed")) }));
        };
        return (
            <Shell title={t("Test the passphrase")} onClose={() => onClose(false)}>
                <form onSubmit={test} className="rep-stack">
                    <p className="bkm-muted">{t("Type the passphrase you have written down to make sure it is the one new backups are encrypted with.")}</p>
                    <input type="password" className="sbk-input" value={check} autoComplete="off" autoFocus
                           onChange={(e) => { setCheck(e.target.value); setState(null); }} aria-label={t("Backup passphrase")} />
                    {state?.result === true && <div className="bkm-note bkm-note-ok" role="status">{t("Correct: this is the current backup passphrase.")}</div>}
                    {state?.result === false && <div className="bkm-note bkm-note-error" role="status">{t("Not correct: this is not the current backup passphrase.")}</div>}
                    {state?.error && <div className="bkm-note bkm-note-error" role="alert">{state.error}</div>}
                    <div className="alr-modal-foot">
                        <button type="button" className="bkm-btn" onClick={() => onClose(false)}>{t("Close")}</button>
                        <button type="submit" className="bkm-btn bkm-btn-primary" disabled={!check || state?.busy}>{t("Test")}</button>
                    </div>
                </form>
            </Shell>
        );
    }

    const level = strength(next);
    const mismatch = again && next !== again;
    const ok = next.length >= MIN && next === again && (mode === "set" || current);
    const save = (e) => {
        e.preventDefault();
        setState({ busy: true });
        api.post("/api/system-backup/passphrase", { passphrase: next, current: mode === "change" ? current : null })
            .then(() => onClose(true))
            .catch((err) => setState({ error: errorText(err, t("Could not save the passphrase")) }));
    };
    return (
        <Shell title={mode === "change" ? t("Change the backup passphrase") : t("Set the backup passphrase")} onClose={() => onClose(false)}>
            <form onSubmit={save} className="rep-stack">
                <div className="bkm-note bkm-note-orange">
                    {t("Without this passphrase no backup can be opened, not even by NGCorion support. Write it down and keep it somewhere outside this server.")}
                </div>
                {mode === "change" && (
                    <>
                        <label className="alr-lbl">
                            {t("Current passphrase")}
                            <input type="password" className="sbk-input" value={current} autoComplete="current-password"
                                   onChange={(e) => setCurrent(e.target.value)} />
                        </label>
                        <p className="alr-hint">{t("Backups made before the change still open on this server without typing the old passphrase; on another server they need the old one.")}</p>
                    </>
                )}
                <label className="alr-lbl">
                    {t("New passphrase")}
                    <input type="password" className="sbk-input" value={next} autoComplete="new-password"
                           onChange={(e) => setNext(e.target.value)} />
                </label>
                <div className="sbk-strength" aria-hidden="true"><i style={{ width: `${level * 25}%`, background: LEVELS[level][1] }} /></div>
                <small className="alr-hint">{next ? LEVELS[level][0] : t("At least {{min}} characters. A sentence of a few words is easy to remember and hard to guess.", { min: MIN })}</small>
                <label className="alr-lbl">
                    {t("Repeat the new passphrase")}
                    <input type="password" className="sbk-input" value={again} autoComplete="new-password"
                           onChange={(e) => setAgain(e.target.value)} aria-invalid={mismatch || undefined} />
                </label>
                {mismatch && <small className="bkm-red">{t("The two passphrases are different.")}</small>}
                {state?.error && <div className="bkm-note bkm-note-error" role="alert">{state.error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={() => onClose(false)}>{t("Cancel")}</button>
                    <button type="submit" className="bkm-btn bkm-btn-primary" disabled={!ok || state?.busy}>{t("Save passphrase")}</button>
                </div>
            </form>
        </Shell>
    );
}

function Shell({ title, onClose, children }) {
    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="sbk-pass-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal">
                <h2 id="sbk-pass-title">{title}</h2>
                {children}
            </div>
        </div>
    );
}
