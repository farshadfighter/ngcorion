import { useCallback, useEffect, useState } from "react";
import { useSelector } from "react-redux";

import api from "../../config/api.js";
import { formatBytes } from "../CVE/cveFormat";
import { errorText } from "../AssetGroups/groupFormat.js";
import { StorageUsage } from "./StorageUsage.jsx";
import { t } from "../../i18n";
import "../../assets/BackupModule.css";

const FIELDS = [
    ["raw_hours", () => t("Raw samples (hours)"), 24, 720],
    ["days_5m", () => t("5-minute averages (days)"), 7, 365],
    ["days_1h", () => t("Hourly averages (days)"), 30, 1095],
    ["days_1d", () => t("Daily averages (days, 0 = for good)"), 0, 3650],
    ["storage_budget_gb", () => t("Disk space at most (GB)"), 1, 500],
];

/**
 * Monitoring storage on the NOC hosts page: what syslog messages and SNMP metrics take against their disk
 * budgets, the disk's free space, and (system administrators) how long each SNMP metrics tier is kept and
 * in how much space. The oldest data goes first when a store passes its budget.
 */
export function NocStoragePanel() {
    const isAdmin = useSelector((s) => s.auth.role) === "admin";
    const [data, setData] = useState(null);
    const [form, setForm] = useState(null);
    const [msg, setMsg] = useState(null);
    const [busy, setBusy] = useState(false);

    const load = useCallback(() => api.get("/api/noc/storage")
        .then(({ data: d }) => { setData(d); setForm(d.metrics_settings); })
        .catch((e) => setMsg({ ok: false, text: errorText(e, t("Could not load the storage figures")) })), []);
    useEffect(() => { load(); }, [load]);

    if (!data || !form) {
        return <section className="bkm-card stg-panel">{msg ? <div className="bkm-note bkm-note-error">{msg.text}</div> : t("Loading...")}</section>;
    }
    const changed = JSON.stringify(form) !== JSON.stringify(data.metrics_settings);
    const save = () => {
        setBusy(true);
        setMsg(null);
        const body = Object.fromEntries(FIELDS.map(([k]) => [k, Number(form[k])]));
        api.put("/api/noc/storage/metrics-settings", body)
            .then(() => { setMsg({ ok: true, text: t("Saved. The next retention run applies it.") }); return load(); })
            .catch((e) => setMsg({ ok: false, text: errorText(e, t("Could not save")) }))
            .finally(() => setBusy(false));
    };
    return (
        <section className="bkm-card stg-panel">
            <h2 className="bkm-h3">{t("Monitoring storage")}</h2>
            <div className="stg-usages">
                <StorageUsage label={t("Syslog messages")} used={data.syslog.used_bytes} budget={data.syslog.budget_bytes}
                              rows={data.syslog.rows} rowsLabel={(r) => t("{{total}} messages", { total: r })} />
                <StorageUsage label={t("SNMP metrics")} used={data.metrics.used_bytes} budget={data.metrics.budget_bytes}
                              rows={data.metrics.rows} rowsLabel={(r) => t("{{total}} samples and averages", { total: r })} />
            </div>
            {data.disk.free_bytes != null && (
                <p className="stg-disk">{t("Free on the server's disk: {{free}}.", { free: formatBytes(data.disk.free_bytes) })}</p>
            )}
            {data.budgets_exceed_free && (
                <div className="bkm-note bkm-note-error">{t("The two budgets allow more than the free disk space: lower them, or free space on the server.")}</div>
            )}
            <p className="bkm-small bkm-muted">
                {t("When a store passes its budget, its oldest data is removed first. The syslog budget and how long messages are kept are in Syslog, Settings.")}
            </p>
            <h3 className="bkm-h3">{t("How long SNMP metrics are kept")}</h3>
            {!isAdmin && <p className="bkm-small bkm-muted">{t("Only a system administrator can change these settings.")}</p>}
            <div className="stg-form">
                {FIELDS.map(([k, label, min, max]) => (
                    <label key={k}>{label()}
                        <input className="bkm-select" type="number" min={min} max={max} value={form[k]} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, [k]: e.target.value })} />
                    </label>
                ))}
            </div>
            <p className="bkm-small bkm-muted">{t("Raw samples are averaged into 5-minute, hourly and daily values; each is kept as long as set here, and charts use the finest one still kept.")}</p>
            {msg && <div className={`bkm-note ${msg.ok ? "bkm-note-ok" : "bkm-note-error"}`}>{msg.text}</div>}
            {isAdmin && (
                <div className="stg-actions">
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !changed} onClick={save}>{t("Save")}</button>
                </div>
            )}
        </section>
    );
}

export default NocStoragePanel;
