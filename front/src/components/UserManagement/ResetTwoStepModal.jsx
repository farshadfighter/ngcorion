/**
 * A system administrator clears another user's two-step sign-in (POST /api/users/{id}/mfa/reset):
 * for someone who lost both the phone and the recovery codes. Their sessions end; if their role
 * requires two-step sign-in they set it up again right after the next password sign-in. Recorded
 * in the audit trail.
 */
import React, { useState } from "react";

import api from "../../config/api";
import { t } from "../../i18n";
import { tx } from "../../i18n/tx";
import { tb } from "../../i18n/backendText";

export const ResetTwoStepModal = ({ user, onClose }) => {
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [done, setDone] = useState(false);

    const reset = async () => {
        setBusy(true);
        setError(null);
        try {
            await api.post(`/api/users/${user.id}/mfa/reset`);
            setDone(true);
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(typeof detail === "string" ? tb(detail) : t("Two-step sign-in could not be reset."));
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="modal-overlay" onClick={() => onClose(done)}>
            <div className="modal-content modal-small" role="dialog" aria-modal="true"
                 aria-labelledby="mfa-reset-title" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3 id="mfa-reset-title">{t("Reset two-step sign-in")}</h3>
                    <button className="modal-close" onClick={() => onClose(done)} aria-label={t("Close")}>✕</button>
                </div>
                <div className="modal-body">
                    {done ? (
                        <p className="tpw-done">
                            <i className="fa-solid fa-circle-check" aria-hidden="true" />{" "}
                            {tx("Two-step sign-in is reset for {{name}}.", { name: <strong>{user.username}</strong> })}
                        </p>
                    ) : (
                        <>
                            <p>{tx("For {{name}}, who lost the phone and the recovery codes.", { name: <strong>{user.username}</strong> })}</p>
                            <ul className="tpw-list">
                                <li>{t("Their authenticator app and recovery codes stop working, and any session they have open ends.")}</li>
                                <li>{t("If their role requires it, they set it up again right after the next sign-in with their password.")}</li>
                                <li>{t("Make sure it is really them asking (in person or by a call you place), not someone who has only their password.")}</li>
                                <li>{t("This is recorded in the audit trail with your name.")}</li>
                            </ul>
                        </>
                    )}
                    {error && <p className="tpw-error" role="alert">{error}</p>}
                    <div className="modal-actions">
                        {done ? (
                            <button type="button" className="btn-submit" onClick={() => onClose(true)}>{t("Done")}</button>
                        ) : (
                            <>
                                <button type="button" className="btn-cancel" onClick={() => onClose(false)}>{t("Cancel")}</button>
                                <button type="button" className="btn-submit" disabled={busy} onClick={reset}>
                                    {busy ? t("Saving…") : t("Reset two-step sign-in")}
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ResetTwoStepModal;
