/**
 * The sidebar menu as data: what is in it, in which order, and who may see each entry.
 *
 * The groups follow the work, in order: know the assets, assess them, fix what was found, keep
 * device backups, watch the network, report; then administration. Each entry names the permission
 * module it needs (the same one its route checks in App.jsx), so a user never sees an entry that
 * would answer "no access"; a group with nothing visible is left out.
 *
 * `key` is the page key menuFromPath() gives for the URL (header title, active state);
 * `keys` lists further page keys that light up the same entry (a page with several URLs).
 */
import { hasPermission } from "../store/authSlice";
import { t } from "../i18n";

// Visible with any one of these read permissions; "admin" = system administrators only; null = everyone.
const any = (...modules) => modules;

export const TOP_ITEMS = [
    { key: "dashboard", label: t("Dashboard"), path: "/overview", icon: "/icons/dashboard.svg", perm: null },
    { key: "alerts", label: t("Alerts"), path: "/alerts", icon: "/icons/alerts.svg", perm: null, badge: "alerts" },
];

export const MENU_GROUPS = [
    {
        id: "assets", label: t("Assets"), icon: "/icons/asset-management.svg",
        items: [
            { key: "asset-management", label: t("Overview"), path: "/assets",
              perm: any("asset_list", "asset_requirement", "asset_auto_discovery") },
            { key: "asset-list", label: t("Asset List"), path: "/assets/inventory", perm: "asset_list" },
            { key: "asset-groups", label: t("Asset groups"), path: "/assets/groups", perm: "asset_list" },
            { key: "software", label: t("Software"), path: "/assets/software", perm: "asset_list" },
            { key: "auto-discovery", label: t("Auto Discovery"), path: "/assets/discovery", perm: "asset_auto_discovery" },
            { key: "schedule-discovery", label: t("Discovery schedules"), path: "/assets/schedule-discovery",
              perm: "asset_auto_discovery" },
            { key: "asset-requirement", label: t("Asset security requirements"), path: "/assets/requirements",
              perm: "asset_requirement" },
        ],
    },
    {
        id: "assessment", label: t("Security assessment"), icon: "/icons/auditing.svg",
        items: [
            { key: "risk-intelligence", label: t("Risk overview"), path: "/risk/overview", perm: "risk" },
            { key: "risk-asset", label: t("Risk Asset"), path: "/risk/assets", perm: "risk" },
            { key: "auditing", label: t("Audit overview"), path: "/audit", perm: "auditing" },
            { key: "operation-device", label: t("Run audits"), path: "/audit/sessions", perm: "auditing" },
            { key: "group-runs", label: t("Group audits"), path: "/audit/group-runs", perm: "auditing" },
            { key: "schedule-auditing", label: t("Audit schedules"), path: "/audit/schedule-auditing", perm: "auditing" },
            { key: "cve", label: t("Vulnerabilities (CVE)"), path: "/cve", perm: "cve" },
        ],
    },
    {
        id: "remediation", label: t("Remediation & hardening"), icon: "/icons/hardening.svg",
        items: [
            { key: "hardening-overview", label: t("Hardening overview"), path: "/hardening/overview", perm: "hardening" },
            { key: "hardening", label: t("Run hardening"), path: "/hardening", perm: "hardening" },
            { key: "remediation", label: t("Remediation"), path: "/remediation", perm: "remediation" },
            { key: "remediation-acceptances", label: t("Accepted Risks"), path: "/remediation/acceptances",
              perm: "remediation" },
            { key: "benchmark-policy", label: t("Benchmark policy"), path: "/remediation/policy", perm: "auditing" },
            { key: "compliance", label: t("Compliance with standards"), path: "/compliance", perm: "auditing" },
        ],
    },
    {
        id: "device-backups", label: t("Device Backups"), icon: "/icons/backup.svg",
        items: [
            { key: "backup-overview", label: t("Overview"), path: "/backup/overview", perm: "backup" },
            { key: "backup", label: t("Backups"), path: "/backup", perm: "backup" },
            { key: "backup-restores", label: t("Restore History"), path: "/backup/restores", perm: "backup" },
            { key: "backup-schedules", keys: ["backup-runs"], label: t("Backup schedules"), path: "/backup/schedules",
              perm: "backup" },
        ],
    },
    {
        id: "network", label: t("Network & monitoring"), icon: "/icons/topology.svg",
        items: [
            { key: "noc-dashboard", label: t("Network status (NOC)"), path: "/noc/dashboard", perm: "noc" },
            { key: "noc-hosts", label: t("Hosts"), path: "/noc/hosts", perm: "noc" },
            { key: "noc-unknown", label: t("Unknown devices"), path: "/noc/unknown-devices", perm: "noc" },
            { key: "noc-syslog", label: t("Syslog"), path: "/noc/syslog", perm: "noc" },
            { key: "topology", label: t("Topology"), path: "/topology", perm: "topology" },
            { key: "design-suggestion", label: t("Suggested Design"), path: "/design-suggestion",
              perm: "design_configuration" },
            { key: "architecture-validation", label: t("Architecture Validation"), path: "/architecture-validation",
              perm: "architecture_validation" },
        ],
    },
    {
        id: "reports", label: t("Reports"), icon: "/icons/reports.svg",
        items: [
            { key: "reports", label: t("Build a report"), path: "/reports", perm: "reports" },
            { key: "reports-archive", label: t("Archive"), path: "/reports/archive", perm: "reports" },
            { key: "reports-schedules", label: t("Schedules"), path: "/reports/schedules", perm: "reports" },
        ],
    },
    {
        id: "admin", label: t("Administration"), icon: "/icons/administration.svg",
        items: [
            { key: "user-management", label: t("Users"), path: "/settings/users", perm: "user_management" },
            { key: "system-configuration", label: t("System Configuration"), path: "/settings/system",
              perm: "system_config" },
            { key: "notifications", label: t("Alert and notification rules"), path: "/settings/notifications",
              perm: "system_config" },
            { key: "cve-database", label: t("Vulnerability database"), path: "/cve/database", perm: "cve" },
            { key: "licence", label: t("License"), path: "/settings/license", perm: "admin" },
            { key: "system-backup", label: t("NGCorion system backup"), path: "/settings/system-backup", perm: "admin" },
            { key: "audit-trail", keys: ["system-logs"], label: t("Logs and audit trail"),
              path: "/settings/audit-trail", perm: "logs" },
        ],
    },
];

/** Whether the signed-in user may see an entry (its route would let them in). */
export function canSee(perm, { role, permissions }) {
    if (perm === null || perm === undefined) return true;
    if (perm === "admin") return role === "admin";
    const modules = Array.isArray(perm) ? perm : [perm];
    return modules.some((m) => hasPermission(permissions, role, m, "read"));
}

/** The top entries and the groups this user sees: entries they may open, groups with any left. */
export function visibleMenu(auth) {
    return {
        top: TOP_ITEMS.filter((i) => canSee(i.perm, auth)),
        groups: MENU_GROUPS
            .map((g) => ({ ...g, items: g.items.filter((i) => canSee(i.perm, auth)) }))
            .filter((g) => g.items.length > 0),
    };
}

/** Whether a menu entry stands for the page with this key. */
export const isActive = (item, pageKey) => item.key === pageKey || (item.keys || []).includes(pageKey);

/** The id of the group holding the page with this key, if any. */
export const groupOf = (pageKey) => MENU_GROUPS.find((g) => g.items.some((i) => isActive(i, pageKey)))?.id;

// Map the current URL path to a stable page key. That key drives the sidebar's active entry, the
// header title and the license badge. More specific paths first.
const PATHS = [
    ["/assets/requirements", "asset-requirement"],
    ["/assets/inventory", "asset-list"],
    ["/assets/groups", "asset-groups"],
    ["/assets/software", "software"],
    ["/assets/discovery", "auto-discovery"],
    ["/assets/schedule-discovery", "schedule-discovery"],
    ["/assets", "asset-management"],
    ["/audit/sessions", "operation-device"],
    ["/audit/schedule-auditing", "schedule-auditing"],
    ["/audit/group-runs", "group-runs"],
    ["/audit", "auditing"],
    ["/hardening/overview", "hardening-overview"],
    ["/hardening", "hardening"],
    ["/remediation/acceptances", "remediation-acceptances"],
    ["/remediation/policy", "benchmark-policy"],
    ["/compliance", "compliance"],
    ["/remediation", "remediation"],
    ["/reports/archive", "reports-archive"],
    ["/reports/schedules", "reports-schedules"],
    ["/reports", "reports"],
    ["/backup/overview", "backup-overview"],
    ["/backup/restores", "backup-restores"],
    ["/backup/schedules", "backup-schedules"],
    ["/backup/runs", "backup-runs"],
    ["/backup", "backup"],
    ["/topology", "topology"],
    ["/design-suggestion", "design-suggestion"],
    ["/architecture-validation", "architecture-validation"],
    ["/design-configuration", "design-configuration"],
    ["/cve/database", "cve-database"],
    ["/cve", "cve"],
    ["/noc/dashboard", "noc-dashboard"],
    ["/noc/hosts", "noc-hosts"],
    ["/noc/syslog", "noc-syslog"],
    ["/noc/unknown-devices", "noc-unknown"],
    ["/settings/users", "user-management"],
    ["/settings/logs", "system-logs"],
    ["/settings/audit-trail", "audit-trail"],
    ["/settings/license", "licence"],
    ["/settings/system-backup", "system-backup"],
    ["/settings/system", "system-configuration"],
    ["/settings/notifications", "notifications"],
    ["/alerts", "alerts"],
    ["/risk/assets", "risk-asset"],
    ["/risk/exposure", "risk-asset"],
    ["/risk/overview", "risk-intelligence"],
];

export const menuFromPath = (pathname) => PATHS.find(([prefix]) => pathname.startsWith(prefix))?.[1] || "dashboard";
