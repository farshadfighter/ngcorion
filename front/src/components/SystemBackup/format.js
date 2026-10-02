import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";

// Labels and helpers shared by the NGCorion backup pages.

export const KIND = {
    scheduled: { label: t("Scheduled"), pill: "sbk-k-sched" },
    manual: { label: t("Manual"), pill: "sbk-k-manual" },
    safety: { label: t("Safety before restore"), pill: "sbk-k-safety" },
    uploaded: { label: t("Uploaded"), pill: "sbk-k-upload" },
};

export const TIER = { daily: t("Daily"), weekly: t("Weekly"), monthly: t("Monthly") };

export const PARTS = {
    essential: {
        label: t("Main data"),
        hint: t("Assets, audits and hardening, device configuration backups, remediation and risk acceptance, users and permissions, alerts and rules, system settings, logs. Always included."),
    },
    reports: { label: t("Report files"), hint: t("PDF and Excel files of archived reports") },
    cve: { label: t("CVE database"), hint: t("Can be rebuilt from an offline package or an online update") },
    noc_history: { label: t("NOC monitoring history"), hint: t("Interface usage and availability samples and rollups") },
};
export const PART_ORDER = ["essential", "reports", "cve", "noc_history"];

export const contentsText = (contents) =>
    contents?.length === PART_ORDER.length ? t("Everything") : (contents || []).map((c) => PARTS[c]?.label || c).join(t(", "));

export const WEEKDAYS = [
    [5, t("Saturday")], [6, t("Sunday")], [0, t("Monday")], [1, t("Tuesday")],
    [2, t("Wednesday")], [3, t("Thursday")], [4, t("Friday")],
];
export const weekday = (d) => (WEEKDAYS.find(([v]) => v === d) || [null, ""])[1];

export function bytes(value) {
    if (value == null) return "—";
    const fmt = (v) => n(v >= 100 ? Math.round(v) : Number(v.toFixed(1)));
    if (value >= 1024 ** 3) return t("{{size}} GB", { size: fmt(value / 1024 ** 3) });
    if (value >= 1024 ** 2) return t("{{size}} MB", { size: fmt(value / 1024 ** 2) });
    if (value >= 1024) return t("{{size}} KB", { size: fmt(value / 1024) });
    return t("{{size}} B", { size: n(value) });
}

export const errorText = (e, fallback) => {
    const d = e?.response?.data?.detail;
    return typeof d === "string" ? tb(d) : fallback;
};

/** Progress text of a backup being written: "Exporting tables: 61 of 79". */
export function backupStep(step) {
    if (!step) return "";
    const m = /^tables (\d+)\/(\d+) (\S+) (\d+)$/.exec(step);
    if (m) return t("Exporting tables: {{done}} of {{total}}", { done: n(Number(m[1])), total: n(Number(m[2])) });
    if (step.startsWith("send ")) return t("Sending to {{name}}", { name: step.slice(5) });
    return {
        prepare: t("Preparing"), database: t("Exporting tables"), files: t("System files and encryption key"),
        encrypt: t("Compressing and encrypting (AES-256-GCM)"), verify: t("Checking: reopening the file and comparing hashes"),
        send: t("Sending to destinations"),
    }[step] || step;
}

/** The table being exported, for the progress list: ["audit_results", 128400]. */
export function backupTable(step) {
    const m = /^tables (\d+)\/(\d+) (\S+) (\d+)$/.exec(step || "");
    return m ? { done: Number(m[1]), total: Number(m[2]), table: m[3], rows: Number(m[4]) } : null;
}

export const RESTORE_STEPS = {
    validate: t("Opening the backup and checking its version"),
    maintenance: t("Entering maintenance mode · pausing background tasks"),
    safety: t("Safety backup of the current state"),
    staging: t("Building an empty database at the backup's version"),
    load: t("Loading tables"),
    check: t("Checking row counts and links between tables"),
    upgrade: t("Upgrading the database if the backup is older"),
    carry: t("Keeping what the backup does not hold"),
    rekey: t("Re-encrypting stored passwords for this server"),
    swap: t("Switching to the restored data"),
    files: t("Restoring system files"),
    finish: t("Leaving maintenance mode"),
    cleanup: t("Removing the test database"),
};

/** Save a backup file through the API (the token travels with the request). */
export async function downloadBackup(b) {
    const res = await api.get(`/api/system-backup/backups/${b.id}/download`, { responseType: "blob" });
    const url = URL.createObjectURL(res.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = b.filename || `ngcorion-${b.id}.ngbak`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function destinationLabel(d) {
    if (d.type === "smb") {
        const path = [d.host, d.share, d.path].filter(Boolean).join("\\");
        return `\\\\${path}`;
    }
    return d.host + (d.port && d.port !== 22 ? `:${d.port}` : "");
}

export const DEST_TYPE = { sftp: "SFTP", smb: t("Windows share") };
