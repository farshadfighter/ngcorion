import { t } from "../../i18n";
// Shared labels and helpers for alerts and notifications.

export const SEVERITY = {
    critical: { label: t("Critical"), pill: "alr-sev-critical", dot: "#b91c1c" },
    warning: { label: t("Warning"), pill: "alr-sev-warning", dot: "#c2410c" },
    info: { label: t("Info"), pill: "alr-sev-info", dot: "#1e3a5f" },
};

export const MODULES = {
    noc: "NOC",
    cve: "CVE",
    audit: t("Audit"),
    backup: t("Backup"),
    remediation: t("Remediation"),
    reports: t("Reports"),
    software: t("Software"),
    system: t("System"),
};

export const CHANNEL_LABEL = {
    email: t("Email"),
    sms: "SMS",
    syslog: t("Syslog"),
    webhook: t("Webhook"),
};

/** What the alert's action button opens. */
export function actionLabel(alert) {
    const link = alert.link || "";
    if (link.startsWith("/noc/hosts")) return t("Open host");
    if (link.startsWith("/cve/database")) return t("Open database");
    if (link.startsWith("/cve")) return t("Open CVE findings");
    if (link.startsWith("/backup/restores")) return t("Open restore");
    if (link.startsWith("/backup")) return t("Open list");
    if (link.startsWith("/audit/sessions")) return t("Open audit");
    if (link.startsWith("/audit") || link.startsWith("/assets/schedule")) return t("Open job");
    if (link.startsWith("/remediation/acceptances")) return t("Open accepted risks");
    if (link.startsWith("/remediation")) return t("Open finding");
    if (link.startsWith("/reports/schedules")) return t("Open schedules");
    if (link.startsWith("/settings/license")) return t("Open license");
    if (link.startsWith("/assets/software")) return t("Open software list");
    return t("View");
}

/** Notify the bell and the sidebar badge that alerts changed here. */
export function announceAlertsChanged() {
    window.dispatchEvent(new Event("alerts:changed"));
}
