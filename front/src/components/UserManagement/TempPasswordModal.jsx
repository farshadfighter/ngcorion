/**
 * A system administrator sets a temporary password for another user (POST /api/users/{id}/reset-password):
 * for someone who forgot theirs and has no email for the self-service reset. The user must choose a
 * new password at the next sign-in, and their open sessions end. The password is shown here once,
 * never stored in the page, and the action is recorded in the audit trail.
 */
import React, { useState } from "react";

import api from "../../config/api";
import { t } from "../../i18n";
import { tx } from "../../i18n/tx";
import { tb } from "../../i18n/backendText";
import { generatePassword, policyProblems } from "./passwordTools.js";

export const TempPasswordModal = ({ user, onClose }) => {
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [visible, setVisible] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [done, setDone] = useState(false);
    const [copied, setCopied] = useState(false);

    const problems = policyProblems(password);
    const mismatch = confirm !== "" && confirm !== password;
    const ready = password && problems.length === 0 && confirm === password && !busy;

    const generate = () => {
        const p = generatePassword();
        setPassword(p);
        setConfirm(p);
        setVisible(true);
        setCopied(false);
    };

    const copy = async () => {
        try {
            await navigator.clipboard.writeText(password);
            setCopied(true);
        } catch {
            setVisible(true); // no clipboard (plain http): the password is on screen to copy by hand
        }
    };

    const submit = async (e) => {
        e.preventDefault();
        if (!ready) return;
        setBusy(true);
        setError(null);
        try {
            await api.post(`/api/users/${user.id}/reset-password`, { new_password: password });
            setDone(true);
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(typeof detail === "string" ? tb(detail) : t("The temporary password could not be set."));
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-small" role="dialog" aria-modal="true"
                 aria-labelledby="temp-pw-title" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3 id="temp-pw-title">{t("Set a temporary password")}</h3>
                    <button className="modal-close" onClick={onClose} aria-label={t("Close")}>✕</button>
                </div>

                {done ? (
                    <div className="modal-body">
                        <p className="tpw-done">
                            <i className="fa-solid fa-circle-check" aria-hidden="true" />{" "}
                            {tx("A temporary password is set for {{name}}.", { name: <strong>{user.username}</strong> })}
                        </p>
                        <ul className="tpw-list">
                            <li>{t("Give it to the user in person or over another safe channel, not by the same email they cannot read.")}</li>
                            <li>{t("They must choose their own password at the next sign-in.")}</li>
                            <li>{t("Any session they still had open has ended.")}</li>
                            <li>{t("This is recorded in the audit trail with your name.")}</li>
                        </ul>
                        <div className="modal-actions">
                            <button type="button" className="btn-submit" onClick={onClose}>{t("Done")}</button>
                        </div>
                    </div>
                ) : (
                    <form className="modal-body" onSubmit={submit}>
                        <p>
                            {tx("For {{name}}, who cannot sign in and cannot use the emailed reset code.", { name: <strong>{user.username}</strong> })}
                        </p>
                        <div className="form-group">
                            <label htmlFor="tpw-new">{t("Temporary password")}</label>
                            <div className="tpw-row">
                                <input id="tpw-new" type={visible ? "text" : "password"} dir="ltr" autoComplete="new-password"
                                       value={password} maxLength={72} aria-invalid={password !== "" && problems.length > 0}
                                       onChange={(e) => { setPassword(e.target.value); setCopied(false); }} />
                                <button type="button" className="tpw-icon" onClick={() => setVisible((v) => !v)}
                                        aria-label={visible ? t("Hide password") : t("Show password")}>
                                    <i className={`fa-solid ${visible ? "fa-eye-slash" : "fa-eye"}`} aria-hidden="true" />
                                </button>
                                <button type="button" className="tpw-icon" onClick={copy} disabled={!password}
                                        aria-label={t("Copy")} title={copied ? t("Copied") : t("Copy")}>
                                    <i className={`fa-solid ${copied ? "fa-check" : "fa-copy"}`} aria-hidden="true" />
                                </button>
                            </div>
                            <button type="button" className="tpw-generate" onClick={generate}>
                                <i className="fa-solid fa-wand-magic-sparkles" aria-hidden="true" /> {t("Generate a strong password")}
                            </button>
                            {password !== "" && problems.length > 0 && (
                                <p className="tpw-hint">{t("Still needed:")} {problems.join("، ")}</p>
                            )}
                        </div>
                        <div className="form-group">
                            <label htmlFor="tpw-confirm">{t("Repeat the password")}</label>
                            <input id="tpw-confirm" type={visible ? "text" : "password"} dir="ltr" autoComplete="new-password"
                                   value={confirm} maxLength={72} aria-invalid={mismatch}
                                   onChange={(e) => setConfirm(e.target.value)} />
                            {mismatch && <p className="tpw-hint">{t("The two passwords are not the same.")}</p>}
                        </div>
                        <p className="warning-text">
                            {t("The user's current password stops working at once, and any session they have open ends.")}
                        </p>
                        {error && <p className="tpw-error" role="alert">{error}</p>}
                        <div className="modal-actions">
                            <button type="button" className="btn-cancel" onClick={onClose}>{t("Cancel")}</button>
                            <button type="submit" className="btn-submit" disabled={!ready}>
                                {busy ? t("Saving…") : t("Set temporary password")}
                            </button>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
};

export default TempPasswordModal;
