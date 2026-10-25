import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";

/*
 * System › Notifications › Delivery policy: what may go out by email and SMS whatever a rule says,
 * and how the password reset code is sent (app/modules/alerts/policy.py).
 */

const LEAST = [
    ["info", t("Every severity")],
    ["warning", t("Warning and Critical")],
    ["critical", t("Critical only")],
];

const RESET = [
    ["email", t("Email"), t("The code goes to the account's email address.")],
    ["sms", t("SMS"), t("The code goes to the account's mobile number; an account without one gets it by email.")],
    ["both", t("Email and SMS"), t("The code goes to both, where the account has a mobile number.")],
];

function Toggle({ on, onChange, label, disabled }) {
    return (
        <label className="alr-pol-toggle">
            <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled}
                    className={`alr-switch ${on ? "is-on" : ""}`} onClick={() => onChange(!on)}>
                <i />
            </button>
            <span>{label}</span>
        </label>
    );
}

function Field({ label, hint, children }) {
    return (
        <div className="alr-pol-field">
            <span className="alr-pol-label">{label}</span>
            {children}
            {hint && <span className="alr-hint">{hint}</span>}
        </div>
    );
}

export function PolicyTab({ canWrite }) {
    const [data, setData] = useState(null);
    const [form, setForm] = useState(null);
    const [error, setError] = useState(null);
    const [saved, setSaved] = useState(false);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        let alive = true;
        api.get("/api/notifications/policy")
            .then(({ data: d }) => { if (alive) { setData(d); setForm(d.config); } })
            .catch((e) => alive && setError(e.response?.data?.detail || t("Could not load the delivery policy")));
        return () => { alive = false; };
    }, []);

    if (!form) {
        return error ? <div className="bkm-note bkm-note-error" role="alert">{tb(error)}</div>
            : <p className="bkm-muted">{t("Loading…")}</p>;
    }

    const set = (part, values) => { setSaved(false); setForm((f) => ({ ...f, [part]: { ...f[part], ...values } })); };
    const quietOn = !!(form.sms.quiet_start && form.sms.quiet_end);
    const changed = JSON.stringify(form) !== JSON.stringify(data.config);
    const s = data.status;
    const off = !canWrite;

    const save = () => {
        setBusy(true);
        setError(null);
        api.put("/api/notifications/policy", form)
            .then(({ data: d }) => { setData(d); setForm(d.config); setSaved(true); })
            .catch((e) => {
                const d = e.response?.data?.detail;
                setError(Array.isArray(d) ? d.map((x) => tb(x.msg.replace(/^Value error, /, ""))).join("; ")
                    : tb(d) || t("Could not save the delivery policy"));
            })
            .finally(() => setBusy(false));
    };

    const notSet = (what) => (
        <span className="bkm-pill bkm-pill-muted" title={t("Set it in System Configuration")}>
            <Link to="/settings/system">{what}</Link>
        </span>
    );

    return (
        <>
            <p className="bkm-muted alr-lead">
                {t("Rules say which alerts go out where; this policy sits above all of them. A message it holds back is listed in the delivery log as Skipped, with the reason.")}
            </p>
            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <div className="alr-pol-grid">
                <section className="bkm-card alr-pol">
                    <header className="alr-pol-head">
                        <h2>{t("Email")}</h2>
                        {s.email_configured ? <span className="bkm-pill bkm-pill-ok">{t("Server set")}</span> : notSet(t("No mail server"))}
                    </header>
                    <Toggle on={form.email.enabled} label={t("Send alerts by email")} disabled={off}
                            onChange={(v) => set("email", { enabled: v })} />
                    <Field label={t("Send for")} hint={t("Alerts below this severity stay in the app.")}>
                        <select className="bkm-select" value={form.email.min_severity} disabled={off || !form.email.enabled}
                                aria-label={t("Least severity for email")}
                                onChange={(e) => set("email", { min_severity: e.target.value })}>
                            {LEAST.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
                        </select>
                    </Field>
                </section>

                <section className="bkm-card alr-pol">
                    <header className="alr-pol-head">
                        <h2>{t("SMS")}</h2>
                        {s.sms_configured ? <span className="bkm-pill bkm-pill-ok">{t("Provider set")}</span> : notSet(t("No SMS provider"))}
                    </header>
                    <Toggle on={form.sms.enabled} label={t("Send alerts by SMS")} disabled={off}
                            onChange={(v) => set("sms", { enabled: v })} />
                    <Field label={t("Send for")} hint={t("SMS costs money and wakes people up: Critical only is a common choice.")}>
                        <select className="bkm-select" value={form.sms.min_severity} disabled={off || !form.sms.enabled}
                                aria-label={t("Least severity for SMS")}
                                onChange={(e) => set("sms", { min_severity: e.target.value })}>
                            {LEAST.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
                        </select>
                    </Field>
                    <Field label={t("Quiet hours")} hint={t("For the rules that set none of their own. Server time.")}>
                        <label className="alr-pol-check">
                            <input type="checkbox" checked={quietOn} disabled={off || !form.sms.enabled}
                                   onChange={(e) => set("sms", e.target.checked ? { quiet_start: "22:00", quiet_end: "07:00" }
                                       : { quiet_start: null, quiet_end: null })} />
                            {t("No SMS at night")}
                        </label>
                        {quietOn && (
                            <span className="alr-row-gap alr-pol-times">
                                <span>{t("from")}</span>
                                <input type="time" className="bkm-select" aria-label={t("Quiet hours start")} value={form.sms.quiet_start}
                                       disabled={off || !form.sms.enabled} onChange={(e) => set("sms", { quiet_start: e.target.value })} />
                                <span>{t("to")}</span>
                                <input type="time" className="bkm-select" aria-label={t("Quiet hours end")} value={form.sms.quiet_end}
                                       disabled={off || !form.sms.enabled} onChange={(e) => set("sms", { quiet_end: e.target.value })} />
                            </span>
                        )}
                        <label className="alr-pol-check">
                            <input type="checkbox" checked={form.sms.critical_in_quiet_hours} disabled={off || !form.sms.enabled}
                                   onChange={(e) => set("sms", { critical_in_quiet_hours: e.target.checked })} />
                            {t("Critical alerts still go out in quiet hours")}
                        </label>
                    </Field>
                    <Field label={t("Daily limit")}
                           hint={t("SMS sent today: {{today}}. 0 = no limit. Over the limit, SMS are skipped until midnight (server time).", { today: s.sms_today })}>
                        <input type="number" className="bkm-select alr-pol-num" min={0} max={100000} step={1}
                               value={form.sms.daily_limit} disabled={off || !form.sms.enabled} aria-label={t("Daily SMS limit")}
                               onChange={(e) => set("sms", { daily_limit: Math.max(0, parseInt(e.target.value || "0", 10) || 0) })} />
                    </Field>
                </section>

                <section className="bkm-card alr-pol">
                    <header className="alr-pol-head">
                        <h2>{t("Password reset code")}</h2>
                    </header>
                    <p className="alr-hint">{t("How the code of “Forgot password” is sent to local accounts.")}</p>
                    <div className="alr-pol-radios" role="radiogroup" aria-label={t("Password reset code")}>
                        {RESET.map(([k, label, hint]) => (
                            <label key={k} className={`alr-pol-radio ${form.password_reset.channel === k ? "is-on" : ""}`}>
                                <input type="radio" name="reset-channel" value={k} checked={form.password_reset.channel === k}
                                       disabled={off} onChange={() => set("password_reset", { channel: k })} />
                                <span><b>{label}</b><span className="alr-hint">{hint}</span></span>
                            </label>
                        ))}
                    </div>
                    {form.password_reset.channel !== "email" && (
                        <p className={`alr-hint ${!s.sms_configured || !s.users_with_phone ? "bkm-orange" : ""}`}>
                            {!s.sms_configured ? t("No SMS provider is set, so the code still goes by email.")
                                : t("Local accounts with a mobile number: {{accounts}}. Numbers are set in User Management.", { accounts: s.users_with_phone })}
                        </p>
                    )}
                </section>
            </div>

            {canWrite && (
                <div className="alr-pol-foot">
                    {saved && !changed && <span className="bkm-green" role="status">{t("Saved. It applies from the next message.")}</span>}
                    <button type="button" className="bkm-btn" disabled={busy || !changed} onClick={() => { setForm(data.config); setError(null); }}>{t("Undo changes")}</button>
                    <button type="button" className="bkm-btn" disabled={busy} onClick={() => { setSaved(false); setForm(data.defaults); }}>{t("Defaults")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !changed} onClick={save}>{busy ? t("Saving…") : t("Save policy")}</button>
                </div>
            )}
        </>
    );
}

export default PolicyTab;
