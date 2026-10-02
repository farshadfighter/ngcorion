import { useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { FREQUENCIES, PERIODS, WEEKDAYS, errorText } from "./reportFormat.js";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Create or edit a schedule. `draft` carries the report settings (template,
 * title, language, formats, classification, params); `schedule` is an
 * existing schedule when editing.
 */
export function ScheduleModal({ draft, schedule, templateTitle, onClose, onSaved }) {
    const base = schedule || draft;
    const [name, setName] = useState(schedule?.name || base.title || tb(templateTitle) || "");
    const [preset, setPreset] = useState(base.params?.period?.preset === "custom" ? "previous_month"
        : (base.params?.period?.preset || "previous_month"));
    const [frequency, setFrequency] = useState(schedule?.frequency || "monthly");
    const [weekday, setWeekday] = useState(schedule?.weekday ?? 5);
    const [monthday, setMonthday] = useState(schedule?.monthday ?? 1);
    const [runTime, setRunTime] = useState(schedule?.run_time || "08:00");
    const [users, setUsers] = useState(schedule?.recipient_users || []);
    const [emails, setEmails] = useState(schedule?.recipient_emails || []);
    const [emailDraft, setEmailDraft] = useState("");
    const [attach, setAttach] = useState(schedule?.attach ?? true);
    const [enabled, setEnabled] = useState(schedule?.enabled ?? true);
    const [people, setPeople] = useState([]);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const first = useRef(null);

    useEffect(() => {
        first.current?.focus();
        api.get("/api/reports/schedules/recipients").then(({ data }) => setPeople(data)).catch(() => {});
    }, []);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);

    const addEmail = () => {
        const e = emailDraft.trim().toLowerCase();
        if (!e) return;
        if (!EMAIL.test(e)) { setError(t("Not an email address: {{email}}", { email: e })); return; }
        if (!emails.includes(e)) setEmails([...emails, e]);
        setEmailDraft("");
        setError(null);
    };

    const save = () => {
        setBusy(true);
        setError(null);
        const payload = {
            name: name.trim(), template: base.template, title: base.title, language: base.language,
            formats: base.formats, classification: base.classification,
            params: { ...base.params, period: { preset } },
            frequency, weekday: frequency === "weekly" ? Number(weekday) : null,
            monthday: ["monthly", "quarterly"].includes(frequency) ? Number(monthday) : null,
            run_time: runTime, recipient_users: users, recipient_emails: emails, attach, enabled,
        };
        const req = schedule ? api.put(`/api/reports/schedules/${schedule.id}`, payload) : api.post("/api/reports/schedules", payload);
        req.then(({ data }) => onSaved(data))
            .catch((e) => setError(errorText(e, t("Could not save the schedule"))))
            .finally(() => setBusy(false));
    };

    const personName = (id) => people.find((p) => p.id === id)?.username || `#${id}`;
    const confidential = base.classification === "confidential";

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="rep-sched-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal rep-modal">
                <h2 id="rep-sched-title">{schedule ? t("Edit schedule") : t("New schedule")}</h2>
                <p className="bkm-muted">{tb(templateTitle)}</p>

                <label className="alr-lbl">{t("Name")}
                    <input ref={first} className="bkm-select" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />
                </label>

                <div className="alr-grid-2">
                    <label className="alr-lbl">{t("How often")}
                        <select className="bkm-select" value={frequency} onChange={(e) => setFrequency(e.target.value)}>
                            {FREQUENCIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Period in each report")}
                        <select className="bkm-select" value={preset} onChange={(e) => setPreset(e.target.value)}>
                            {PERIODS.filter(([v]) => v !== "custom").map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                        </select>
                    </label>
                    {frequency === "weekly" && (
                        <label className="alr-lbl">{t("Day")}
                            <select className="bkm-select" value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>
                                {WEEKDAYS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                            </select>
                        </label>
                    )}
                    {["monthly", "quarterly"].includes(frequency) && (
                        <label className="alr-lbl">{frequency === "monthly" ? t("Day of the month") : t("Day of the quarter's first month")}
                            <input type="number" className="bkm-select" min={1} max={28} value={monthday}
                                   onChange={(e) => setMonthday(e.target.value)} />
                        </label>
                    )}
                    <label className="alr-lbl">{t("Time")}
                        <input type="time" className="bkm-select" value={runTime} onChange={(e) => setRunTime(e.target.value)} />
                    </label>
                </div>
                <p className="alr-hint">{base.language === "fa"
                    ? t("Months and quarters follow the Solar Hijri calendar because the report is in Persian.")
                    : t("Months and quarters follow the Gregorian calendar because the report is in English.")}</p>

                <div className="alr-lbl">{t("Recipients")}
                    <div className="bkm-row-gap">
                        {users.map((id) => (
                            <span key={`u${id}`} className="rep-chip-x">{personName(id)}
                                <button type="button" aria-label={t("Remove {{name}}", { name: personName(id) })}
                                        onClick={() => setUsers(users.filter((u) => u !== id))}>×</button></span>
                        ))}
                        {emails.map((e) => (
                            <span key={e} className="rep-chip-x bidi-auto">{e}
                                <button type="button" aria-label={t("Remove {{name}}", { name: e })}
                                        onClick={() => setEmails(emails.filter((x) => x !== e))}>×</button></span>
                        ))}
                    </div>
                    <div className="alr-grid-2">
                        <select className="bkm-select" value="" aria-label={t("Add a user")}
                                onChange={(e) => e.target.value && setUsers([...new Set([...users, Number(e.target.value)])])}>
                            <option value="">{t("Add a user…")}</option>
                            {people.filter((p) => !users.includes(p.id)).map((p) => (
                                <option key={p.id} value={p.id} disabled={!p.has_email}>
                                    {p.username}{p.has_email ? "" : ` (${t("no email")})`}
                                </option>
                            ))}
                        </select>
                        <div className="bkm-row-gap">
                            <input type="email" className="bkm-select" style={{ flex: 1, minWidth: 0 }} value={emailDraft}
                                   placeholder="name@company.com" aria-label={t("Email address")}
                                   onChange={(e) => setEmailDraft(e.target.value)}
                                   onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addEmail(); } }} />
                            <button type="button" className="bkm-btn bkm-btn-sm" onClick={addEmail}>{t("Add")}</button>
                        </div>
                    </div>
                    {confidential && emails.length > 0 && (
                        <p className="alr-hint bkm-orange">{t("This report is confidential: it is sent only to users of NGCorion, not to the other addresses.")}</p>
                    )}
                </div>

                <label className="rep-check" style={{ cursor: "pointer" }}>
                    <input type="checkbox" checked={attach} onChange={(e) => setAttach(e.target.checked)} />
                    <span>{t("Attach the file to the email")}<small>{t("Up to 10 MB; a larger report is announced without the file.")}</small></span>
                </label>
                <label className="rep-check" style={{ cursor: "pointer" }}>
                    <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                    <span>{t("Enabled")}</span>
                </label>
                <p className="alr-hint">{t("Emails go out through the SMTP server set in System Configuration. If a run fails, an alert is raised for the owner of the schedule.")}</p>

                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !name.trim() || (!users.length && !emails.length)}
                            onClick={save}>{busy ? t("Saving…") : t("Save schedule")}</button>
                </div>
            </div>
        </div>
    );
}
