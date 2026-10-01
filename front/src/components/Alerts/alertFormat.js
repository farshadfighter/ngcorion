// Shared labels and helpers for alerts and notifications.

export const SEVERITY = {
    critical: { label: "Critical", pill: "alr-sev-critical", dot: "#b91c1c" },
    warning: { label: "Warning", pill: "alr-sev-warning", dot: "#c2410c" },
    info: { label: "Info", pill: "alr-sev-info", dot: "#1e3a5f" },
};

export const MODULES = {
    noc: "NOC",
    cve: "CVE",
    audit: "Audit",
    backup: "Backup",
    system: "System",
};

export const CHANNEL_LABEL = {
    email: "Email",
    sms: "SMS",
    syslog: "Syslog",
    webhook: "Webhook",
};

/** What the alert's action button opens. */
export function actionLabel(alert) {
    const link = alert.link || "";
    if (link.startsWith("/noc/hosts")) return "Open host";
    if (link.startsWith("/cve/database")) return "Open database";
    if (link.startsWith("/cve")) return "Open findings";
    if (link.startsWith("/backup/restores")) return "Open restore";
    if (link.startsWith("/backup")) return "Open list";
    if (link.startsWith("/audit/sessions")) return "Open audit";
    if (link.startsWith("/audit") || link.startsWith("/assets/schedule")) return "Open job";
    if (link.startsWith("/settings/license")) return "Open license";
    return "Open";
}

/** Notify the bell and the sidebar badge that alerts changed here. */
export function announceAlertsChanged() {
    window.dispatchEvent(new Event("alerts:changed"));
}
