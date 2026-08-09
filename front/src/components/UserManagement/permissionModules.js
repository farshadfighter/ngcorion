/**
 * Modules that can be granted per-user permissions.
 *
 * Names must match ModuleEnum in app/models/user_permission.py — the backend
 * rejects anything else. Shared by AddUserModal and EditUserModal so the two
 * lists cannot drift apart.
 */
export const PERMISSION_MODULES = [
    { name: "dashboard",            label: "Dashboard",         icon: "⊞" },
    { name: "asset_requirement",    label: "Asset Requirement", icon: "◈" },
    { name: "asset_list",           label: "Asset List",        icon: "≡" },
    { name: "asset_auto_discovery", label: "Auto Discovery",    icon: "⟳" },
    { name: "user_management",      label: "User Management",   icon: "◎" },
    { name: "hardening",            label: "Hardening",         icon: "🛡" },
    { name: "auditing",             label: "Auditing",          icon: "📋" },
    { name: "risk",                 label: "Risk Intelligence", icon: "⚠" },
];

export default PERMISSION_MODULES;
