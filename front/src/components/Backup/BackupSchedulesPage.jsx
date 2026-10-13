/**
 * Backup schedules (/backup/schedules): recurring configuration backups of asset groups (the shared
 * scheduled-jobs page, job type "backup"), and how long backups identical to the previous one are
 * kept (GET/PUT /api/backups/settings).
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { n, t } from "../../i18n";
import { ScheduledJobsPage } from "../Scheduling/ScheduledJobsPage.jsx";
import { errorText } from "../AssetGroups/groupFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/AssetGroups.css";

function Retention() {
    const canWrite = usePermission("backup", "write");
    const [days, setDays] = useState(null);
    const [saved, setSaved] = useState(null);
    const [error, setError] = useState(null);
    useEffect(() => {
        api.get("/api/backups/settings").then(({ data }) => { setDays(data.retention_days); setSaved(data.retention_days); })
            .catch(() => {});
    }, []);
    if (days === null) return null;
    const save = () => {
        setError(null);
        api.put("/api/backups/settings", { retention_days: Number(days) })
            .then(({ data }) => { setDays(data.retention_days); setSaved(data.retention_days); })
            .catch((e) => setError(errorText(e, t("Could not save"))));
    };
    return (
        <section className="bkm-card bk-retention">
            <div>
                <b>{t("Keeping backups")}</b>
                <p className="bkm-small bkm-muted">{t("An unchanged configuration is never stored twice, and every version with a change is kept. Backups identical to the previous one (taken by hand, for example) are removed after the period below; the latest backup of each device, the first one and those used by a hardening or restore always stay.")}</p>
            </div>
            <div className="bk-retention-row">
                <label className="alr-lbl">{t("Remove identical copies after (days)")}
                    <input className="bkm-select" type="number" min={7} max={3650} value={days} disabled={!canWrite}
                           onChange={(e) => setDays(e.target.value)} />
                </label>
                {canWrite && <button type="button" className="bkm-btn" disabled={Number(days) === saved} onClick={save}>{t("Save")}</button>}
                {Number(days) === saved && <span className="bkm-small bkm-muted">{t("{{value}} days", { value: n(saved) })}</span>}
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
        </section>
    );
}

export function BackupSchedulesPage() {
    return (
        <ScheduledJobsPage key="backup" jobType="backup" footer={(
            <div className="bk-sched-foot">
                <Link className="bkm-link" to="/backup/runs">{t("Backup runs")} ›</Link>
                <Retention />
            </div>
        )} />
    );
}

export default BackupSchedulesPage;
