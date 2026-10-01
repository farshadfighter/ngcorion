import { uiLocale, t } from "../../i18n";
/* Shared by the backup list and the restore wizard. Kept out of the .jsx
   files so they only export components (react-refresh). */

// Device families the backend can restore (drivers.SUPPORTED_FAMILIES).
export const FAMILY_LABELS = {
    cisco: 'Cisco',
    fortinet: 'FortiGate',
    linux: 'Linux',
    apache: 'Apache',
    mongodb: 'MongoDB',
};

export const isRestorable = (deviceType) =>
    Object.prototype.hasOwnProperty.call(FAMILY_LABELS, (deviceType || '').toLowerCase());

export const familyLabel = (deviceType) =>
    FAMILY_LABELS[(deviceType || '').toLowerCase()] || deviceType || t("Unknown");

export const SOURCE_LABELS = {
    manual: t("Manual"),
    hardening: t("Before hardening"),
    pre_restore: t("Before restore"),
};

export const sourceLabel = (source) => SOURCE_LABELS[source] || source || '-';

// Mirrors RESTORE_ACTIVE_STATUSES / RESTORE_FINAL_STATUSES in the backend.
export const ACTIVE_RESTORE_STATUSES = [
    'queued', 'connecting', 'backing_up', 'applying', 'verifying', 'saving', 'reverting',
];

export const RESTORE_STATUS_LABELS = {
    queued: t("Queued"),
    connecting: t("Connecting"),
    backing_up: t("Backing up"),
    applying: t("Applying"),
    verifying: t("Verifying"),
    saving: t("Saving"),
    reverting: t("Reverting"),
    succeeded: t("Succeeded"),
    reverted: t("Reverted"),
    failed: t("Failed"),
};

// How each family reverts on its own if NGCorion loses the device.
export const AUTO_REVERT_TEXT = {
    cisco: t("IOS applies the changes under a revert timer (configure terminal revert timer). If NGCorion cannot reconnect and confirm in time, the device rolls back to its current configuration."),
    fortinet: t("FortiGate applies the changes in revert mode without saving them. If NGCorion cannot reconnect over SSH and confirm within the timer, the device returns to its current configuration on its own."),
    linux: t("The current files are snapshotted on the host and a timer restores them unless NGCorion reconnects and confirms in time."),
    apache: t("The current files are snapshotted on the host and a timer restores them unless NGCorion reconnects and confirms in time."),
    mongodb: t("The current files are snapshotted on the host and a timer restores them unless NGCorion reconnects and confirms in time."),
};

/* FastAPI errors arrive as a string, an SSH error object
   ({message, suggestions}) or a validation array. */
export const errorText = (err, fallback) => {
    const detail = err?.response?.data?.detail;
    if (!detail) return fallback;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return detail.map((d) => d.msg || String(d)).join('; ');
    if (detail.message) {
        const tips = Array.isArray(detail.suggestions) && detail.suggestions.length
            ? ` — ${detail.suggestions[0]}` : '';
        return detail.message + tips;
    }
    return fallback;
};

export const formatDateTime = (ts) => {
    if (!ts) return '-';
    return new Date(ts).toLocaleString(uiLocale(),  {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
    });
};

export const formatTime = (ts) => {
    if (!ts) return '';
    return new Date(ts).toLocaleTimeString(uiLocale(),  { hour12: false });
};
