import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { currentLanguage, t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDateTime } from "../../utils/dates.js";
import { FREQUENCIES, WEEKDAYS, errorText, label, periodText } from "./reportFormat.js";
import { ScheduleModal } from "./ScheduleModal.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Reports.css";

function when(s) {
    const at = n(s.run_time);
    if (s.frequency === "daily") return t("Every day at {{time}}", { time: at });
    if (s.frequency === "weekly") return t("Every {{day}} at {{time}}", { day: label(WEEKDAYS, s.weekday), time: at });
    if (s.frequency === "monthly") return t("Day {{day}} of every month at {{time}}", { day: n(s.monthday), time: at });
    return t("Day {{day}} of every quarter at {{time}}", { day: n(s.monthday), time: at });
}

const LAST = {
    sent: { label: t("Sent"), pill: "rep-st-ok" },
    running: { label: t("Being built"), pill: "rep-st-run" },
    ready: { label: t("Built"), pill: "rep-st-ok" },
    failed: { label: t("Failed"), pill: "rep-st-fail" },
};

/** Reports built and emailed on a timetable. */
export function ReportSchedules() {
    const canWrite = usePermission("reports", "write");
    const [rows, setRows] = useState(null);
    const [titles, setTitles] = useState({});
    const [error, setError] = useState(null);
    const [notice, setNotice] = useState(null);
    const [editing, setEditing] = useState(null);
    const [confirm, setConfirm] = useState(null);
    const [busy, setBusy] = useState(null);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((x) => x + 1), []);

    useEffect(() => {
        api.get("/api/reports/schedules/list")
            .then(({ data }) => { setRows(data); setError(null); })
            .catch(() => setError(t("Could not load the schedules")));
    }, [reload]);

    useEffect(() => {
        api.get("/api/reports/catalog")
            .then(({ data }) => setTitles(Object.fromEntries(data.templates.map((x) => [x.id, x.title]))))
            .catch(() => {});
    }, []);

    const toggle = (s) => {
        setBusy(s.id);
        api.put(`/api/reports/schedules/${s.id}`, { ...s, enabled: !s.enabled })
            .then(refresh).catch((e) => setError(errorText(e, t("Could not save the schedule")))).finally(() => setBusy(null));
    };
    const runNow = (s) => {
        setBusy(s.id);
        setNotice(null);
        api.post(`/api/reports/schedules/${s.id}/run`)
            .then(({ data }) => { setNotice(t("{{code}} is being built and will be emailed when it is ready.", { code: data.report.code })); refresh(); })
            .catch((e) => setError(errorText(e, t("The schedule could not run")))).finally(() => setBusy(null));
    };
    const remove = (s) => {
        setConfirm(null);
        setBusy(s.id);
        api.delete(`/api/reports/schedules/${s.id}`)
            .then(refresh).catch((e) => setError(errorText(e, t("Could not delete the schedule")))).finally(() => setBusy(null));
    };

    const sep = currentLanguage() === "fa" ? "، " : ", ";

    return (
        <div className="bkm-page">
            <div className="bkm-head rep-head">
                <div>
                    <div className="bkm-crumb"><Link to="/reports">{t("Reports")}</Link> › {t("Schedules")}</div>
                    <h1>{t("Report schedules")}</h1>
                    <p>{t("Reports built and emailed automatically. Each schedule runs with the permissions of its owner at the time it runs.")}</p>
                </div>
                {canWrite && <Link className="bkm-btn bkm-btn-primary" to="/reports">{t("New schedule from a report")}</Link>}
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
            {notice && <div className="bkm-note bkm-note-ok" role="status">{notice}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table rep-table">
                        <thead>
                            <tr>
                                <th>{t("Name")}</th>
                                <th style={{ width: 200 }}>{t("When")}</th>
                                <th style={{ width: 170 }}>{t("Recipients")}</th>
                                <th style={{ width: 170 }}>{t("Last run")}</th>
                                <th style={{ width: 120 }}>{t("Next run")}</th>
                                <th style={{ width: 80 }}>{t("Enabled")}</th>
                                <th style={{ width: 150 }}><span className="sr-only">{t("Actions")}</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {(rows || []).map((s) => (
                                <tr key={s.id}>
                                    <td>
                                        <b className="bidi-auto">{s.name}</b>
                                        <span className="bkm-sub">{tb(titles[s.template] || s.template)} · {s.formats.map((f) => (f === "pdf" ? "PDF" : "Excel")).join(" + ")} · {s.language === "fa" ? t("Persian") : t("English")}</span>
                                        <span className="bkm-sub">{t("Owner")}: {s.owner}</span>
                                    </td>
                                    <td>{when(s)}<span className="bkm-sub">{t("Period in each report")}: {periodText(s.params)}</span>
                                        <span className="bkm-sub">{label(FREQUENCIES, s.frequency)}</span></td>
                                    <td>
                                        {t("{{count}} recipients", { count: s.recipient_names.length + s.recipient_emails.length })}
                                        <span className="bkm-sub bidi-auto">{[...s.recipient_names, ...s.recipient_emails].join(sep)}</span>
                                    </td>
                                    <td>
                                        {s.last_status ? <span className={`bkm-pill ${LAST[s.last_status]?.pill}`}>{LAST[s.last_status]?.label}</span> : "—"}
                                        {s.last_run_at && <span className="bkm-sub">{formatDateTime(s.last_run_at)}</span>}
                                        {s.last_error && <span className="bkm-sub bkm-red">{tb(s.last_error)}</span>}
                                    </td>
                                    <td>{s.enabled && s.next_run_at ? formatDateTime(s.next_run_at) : "—"}</td>
                                    <td>
                                        <label className="rep-switch" title={s.enabled ? t("Enabled") : t("Disabled")}>
                                            <input type="checkbox" checked={s.enabled} disabled={!canWrite || busy === s.id} onChange={() => toggle(s)}
                                                   aria-label={t("Enable {{name}}", { name: s.name })} />
                                            <span />
                                        </label>
                                    </td>
                                    <td>
                                        {canWrite && (
                                            <div className="alr-row-actions">
                                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === s.id} onClick={() => setEditing(s)}>{t("Edit")}</button>
                                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === s.id} onClick={() => runNow(s)}>{t("Run now")}</button>
                                                <button type="button" className="bkm-btn bkm-btn-sm alr-danger" disabled={busy === s.id} onClick={() => setConfirm(s)}>{t("Delete")}</button>
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                            {rows && rows.length === 0 && (
                                <tr><td colSpan={7}>
                                    <div className="bkm-empty">
                                        <b>{t("No schedule yet")}</b>
                                        <span>{t("Open a report, choose its settings and press “Save as a schedule…”.")}</span>
                                    </div>
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </section>

            {editing && (
                <ScheduleModal schedule={editing} templateTitle={titles[editing.template] || editing.template}
                               onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />
            )}
            {confirm && (
                <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="rep-sdel-title">
                    <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => setConfirm(null)} />
                    <div className="alr-modal">
                        <h2 id="rep-sdel-title">{t("Delete this schedule?")}</h2>
                        <p><b className="bidi-auto">{confirm.name}</b></p>
                        <p className="bkm-muted">{t("Reports it already built stay in the archive.")}</p>
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={() => setConfirm(null)}>{t("Cancel")}</button>
                            <button type="button" className="bkm-btn alr-danger" onClick={() => remove(confirm)}>{t("Delete")}</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
