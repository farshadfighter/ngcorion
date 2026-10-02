import { useEffect, useState } from "react";
import { t, n } from "../../i18n";
import { RESTORE_STEPS } from "./format.js";
import "../../assets/SystemBackup.css";

/**
 * Shown to everyone while a backup is being restored: the API answers 503
 * with a "maintenance" body (app/modules/sysbackup/maintenance.py), the shared
 * API client turns that into an "ngc-maintenance" event, and this overlay
 * waits for the restore to end, then reloads the page.
 */
export function MaintenanceOverlay() {
    const [state, setState] = useState(null);

    useEffect(() => {
        const on = (e) => {
            if (document.body.dataset.restoreWizard === "1") return;     // the wizard shows it already
            setState(e.detail || {});
        };
        window.addEventListener("ngc-maintenance", on);
        return () => window.removeEventListener("ngc-maintenance", on);
    }, []);

    const active = state !== null;
    useEffect(() => {
        if (!active) return undefined;
        let alive = true;
        let timer;
        const tick = async () => {
            try {
                const token = localStorage.getItem("token");
                const res = await fetch("/api/system-backup/maintenance",
                    { headers: token ? { Authorization: `Bearer ${token}` } : {} });
                const body = res.status === 200 || res.status === 503 ? await res.json() : null;
                if (body?.maintenance) {
                    if (alive) setState(body.maintenance);
                } else if (res.status !== 502 && res.status !== 504) {
                    window.location.reload();            // the restore is over
                    return;
                }
            } catch { /* the server may be restarting */ }
            if (alive) timer = setTimeout(tick, 2000);
        };
        timer = setTimeout(tick, 1500);
        return () => { alive = false; clearTimeout(timer); };
    }, [active]);

    if (!active) return null;
    return (
        <div className="sbk-maint" role="alertdialog" aria-modal="true" aria-labelledby="sbk-maint-title">
            <div>
                <h2 id="sbk-maint-title">{t("NGCorion is restoring a backup")}</h2>
                <p>{t("The system is in maintenance mode for a few minutes and will be back on its own. This page reloads when the restore ends.")}</p>
                {state.step && <p><b>{RESTORE_STEPS[state.step] || state.step}</b></p>}
                <div className="sbk-bar" aria-hidden="true"><i style={{ width: `${Math.max(state.progress || 0, 3)}%` }} /></div>
                {state.progress != null && <p>{t("{{pct}}%", { pct: n(state.progress) })}</p>}
            </div>
        </div>
    );
}
