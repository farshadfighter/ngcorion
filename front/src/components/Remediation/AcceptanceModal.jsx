import { useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { formatDate } from "../../utils/dates.js";
import { SEVERITY, errorText } from "./remediationFormat.js";

const dayOffset = (days) => {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString().slice(0, 10);
};

/** Ask for a risk acceptance: why, what compensates, until when. Someone else approves it. */
export function AcceptanceModal({ item, onClose, onSent }) {
    const maxDays = item.accept_max_days || 30;
    const [scope, setScope] = useState("item");
    const [justification, setJustification] = useState("");
    const [control, setControl] = useState("");
    const [until, setUntil] = useState(dayOffset(maxDays));
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const first = useRef(null);

    useEffect(() => { first.current?.focus(); }, []);

    const send = () => {
        setBusy(true);
        setError(null);
        api.post(`/api/remediation/items/${item.id}/acceptances`, {
            scope, justification: justification.trim(), compensating_control: control.trim() || null, expires_on: until,
        })
            .then(onSent)
            .catch((e) => setError(errorText(e, t("Could not send the request"))))
            .finally(() => setBusy(false));
    };

    const scopeLabel = item.source === "cve" ? t("This CVE on every asset")
        : item.source === "audit" ? t("This check on every asset") : t("This rule on every asset");
    const valid = justification.trim().length >= 10 && until;

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="rem-acc-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal rem-modal">
                <h2 id="rem-acc-title">{t("Request risk acceptance")}</h2>
                <p className="bkm-muted"><span className="bkm-mono">{item.ref}</span> · {item.asset_name} · {SEVERITY[item.severity]?.label}</p>

                <div className="alr-lbl">{t("Scope")}
                    <div className="rem-radio" role="radiogroup" aria-label={t("Scope")}>
                        <button type="button" role="radio" aria-checked={scope === "item"} className={scope === "item" ? "is-on" : ""} onClick={() => setScope("item")}>
                            {t("This finding only")}<small>{item.ref} · {item.asset_name}</small>
                        </button>
                        <button type="button" role="radio" aria-checked={scope === "ref"} className={scope === "ref" ? "is-on" : ""} onClick={() => setScope("ref")}>
                            {scopeLabel}<small>{t("Assets where it appears later are covered too")}</small>
                        </button>
                    </div>
                </div>
                <label className="alr-lbl">{t("Justification")}
                    <textarea ref={first} className="bkm-select" rows={3} maxLength={4000} value={justification}
                              onChange={(e) => setJustification(e.target.value)}
                              placeholder={t("Why this cannot be fixed now")} />
                </label>
                <label className="alr-lbl">{t("Compensating control")}
                    <textarea className="bkm-select" rows={2} maxLength={4000} value={control}
                              onChange={(e) => setControl(e.target.value)}
                              placeholder={t("What reduces the risk meanwhile (optional)")} />
                </label>
                <label className="alr-lbl">{t("Until")}
                    <input type="date" className="bkm-select" value={until} min={dayOffset(1)} max={dayOffset(maxDays)}
                           onChange={(e) => setUntil(e.target.value)} />
                    <span className="alr-hint">
                        {until ? formatDate(`${until}T12:00:00`) : ""} · {t("At most {{days}} days for this severity", { days: maxDays })}
                    </span>
                </label>
                <p className="alr-hint">{t("An administrator or manager other than you approves the request. When it ends, the finding opens again and counts in the risk score.")}</p>
                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !valid} onClick={send}>
                        {busy ? t("Sending…") : t("Send for approval")}
                    </button>
                </div>
            </div>
        </div>
    );
}
