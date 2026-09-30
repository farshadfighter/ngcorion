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
    FAMILY_LABELS[(deviceType || '').toLowerCase()] || deviceType || 'Unknown';

export const SOURCE_LABELS = {
    manual: 'Manual',
    hardening: 'Before hardening',
    pre_restore: 'Before restore',
};

export const sourceLabel = (source) => SOURCE_LABELS[source] || source || '-';

// Mirrors RESTORE_ACTIVE_STATUSES / RESTORE_FINAL_STATUSES in the backend.
export const ACTIVE_RESTORE_STATUSES = [
    'queued', 'connecting', 'backing_up', 'applying', 'verifying', 'saving', 'reverting',
];

export const RESTORE_STATUS_LABELS = {
    queued: 'Queued',
    connecting: 'Connecting',
    backing_up: 'Backing up',
    applying: 'Applying',
    verifying: 'Verifying',
    saving: 'Saving',
    reverting: 'Reverting',
    succeeded: 'Succeeded',
    reverted: 'Reverted',
    failed: 'Failed',
};

// How each family reverts on its own if NGCorion loses the device.
export const AUTO_REVERT_TEXT = {
    cisco: 'IOS applies the changes under a revert timer (configure terminal revert timer). '
        + 'If NGCorion cannot reconnect and confirm in time, the device rolls back to its current configuration.',
    fortinet: 'FortiGate applies the changes in revert mode without saving them. If NGCorion cannot '
        + 'reconnect over SSH and confirm within the timer, the device returns to its current configuration on its own.',
    linux: 'The current files are snapshotted on the host and a timer restores them unless NGCorion '
        + 'reconnects and confirms in time.',
    apache: 'The current files are snapshotted on the host and a timer restores them unless NGCorion '
        + 'reconnects and confirms in time.',
    mongodb: 'The current files are snapshotted on the host and a timer restores them unless NGCorion '
        + 'reconnects and confirms in time.',
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
    return new Date(ts).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
    });
};

export const formatTime = (ts) => {
    if (!ts) return '';
    return new Date(ts).toLocaleTimeString('en-GB', { hour12: false });
};
