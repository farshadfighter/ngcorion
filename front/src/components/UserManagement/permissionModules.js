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
    { name: "dashboard",            label: "Dashboard",         icon: "fa-solid fa-table-columns" },
    { name: "asset_requirement",    label: "Asset Requirement", icon: "fa-solid fa-clipboard-list" },
    { name: "asset_list",           label: "Asset List",        icon: "fa-solid fa-server" },
    { name: "asset_auto_discovery", label: "Auto Discovery",    icon: "fa-solid fa-tower-broadcast" },
    { name: "user_management",      label: "User Management",   icon: "fa-solid fa-users-gear" },
    { name: "hardening",            label: "Hardening",         icon: "fa-solid fa-shield-halved" },
    { name: "auditing",             label: "Auditing",          icon: "fa-solid fa-list-check" },
    { name: "risk",                 label: "Risk Intelligence", icon: "fa-solid fa-triangle-exclamation" },
    { name: "system_config",        label: "System Config",     icon: "fa-solid fa-sliders" },
    { name: "logs",                 label: "System Log",        icon: "fa-solid fa-file-lines" },
    { name: "backup",               label: "Configuration Backup", icon: "fa-solid fa-database" },
    { name: "topology",             label: "Topology",          icon: "fa-solid fa-diagram-project" },
    { name: "architecture_validation", label: "Architecture Validation", icon: "fa-solid fa-clipboard-check" },
    { name: "design_configuration", label: "Design & Configuration", icon: "fa-solid fa-drafting-compass" },
    // Deployment is intentionally NOT listed here: it is gated by role
    // (admin/manager) only, not by a per-user module permission, so granting
    // it here would be a dead control that does nothing on the backend.
    { name: "drift",                label: "Configuration Drift", icon: "fa-solid fa-arrows-split-up-and-left" },
    { name: "cve",                  label: "CVE",                icon: "fa-solid fa-bug" },
    { name: "noc",                  label: "NOC",                icon: "fa-solid fa-satellite-dish" },
];

export default PERMISSION_MODULES;
