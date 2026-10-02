import { t } from "../../i18n";
/**
 * Modules that can be granted per-user permissions.
 *
 * Names must match ModuleEnum in app/models/user_permission.py — the backend
 * rejects anything else. Shared by AddUserModal and EditUserModal so the two
 * lists cannot drift apart.
 *
 * `icon` is a Font Awesome class rather than a literal glyph: the emoji and
 * geometric characters used before rendered inconsistently across systems (and
 * not at all where the font lacked them).
 */
export const PERMISSION_MODULES = [
    { name: "dashboard",            label: t("Dashboard"),         icon: "fa-solid fa-table-columns" },
    { name: "asset_requirement",    label: t("Asset Requirement"), icon: "fa-solid fa-clipboard-list" },
    { name: "asset_list",           label: t("Asset List"),        icon: "fa-solid fa-server" },
    { name: "asset_auto_discovery", label: t("Auto Discovery"),    icon: "fa-solid fa-tower-broadcast" },
    { name: "user_management",      label: t("User Management"),   icon: "fa-solid fa-users-gear" },
    { name: "hardening",            label: t("Hardening"),         icon: "fa-solid fa-shield-halved" },
    { name: "auditing",             label: t("Auditing"),          icon: "fa-solid fa-list-check" },
    { name: "risk",                 label: t("Risk Intelligence"), icon: "fa-solid fa-triangle-exclamation" },
    { name: "system_config",        label: t("System Config"),     icon: "fa-solid fa-sliders" },
    { name: "logs",                 label: t("System Log"),        icon: "fa-solid fa-file-lines" },
    { name: "backup",               label: t("Backup & Restore"), icon: "fa-solid fa-database" },
    { name: "topology",             label: t("Topology"),          icon: "fa-solid fa-diagram-project" },
    { name: "architecture_validation", label: t("Architecture Validation"), icon: "fa-solid fa-clipboard-check" },
    { name: "design_configuration", label: t("Design & Configuration"), icon: "fa-solid fa-drafting-compass" },
    // Deployment is intentionally NOT listed here: it is gated by role
    // (admin/manager) only, not by a per-user module permission, so granting
    // it here would be a dead control that does nothing on the backend.
    // Configuration Drift is also not listed: its frontend page was removed
    // (product decision), so granting this permission has nothing left to
    // gate in the UI - same reasoning as Deployment above.
    { name: "cve",                  label: t("CVE"),                icon: "fa-solid fa-bug" },
    { name: "noc",                  label: t("NOC"),                icon: "fa-solid fa-satellite-dish" },
    { name: "remediation",          label: t("Remediation"),        icon: "fa-solid fa-clipboard-check" },
];

export default PERMISSION_MODULES;
