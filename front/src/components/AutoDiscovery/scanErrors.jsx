/**
 * Scan error presentation.
 *
 * A missing nmap binary is an operator problem, not a user problem: the backend
 * raises FileNotFoundError("nmap is not installed or not in PATH") from
 * NmapScanner.build_nmap_command, which reaches the UI verbatim as
 * scan.error / scan.error_message (and as a 500 detail on rejected thunks).
 * That string tells the operator nothing actionable, so it is swapped for a
 * Persian message naming the exact command that fixes it.
 */

import React from 'react';

/**
 * Normalize whatever the API or a rejected thunk handed us into plain text.
 * The value may be a string, a FastAPI validation array, or an error object.
 */
export const errorToText = (error) => {
    if (!error) return '';
    if (typeof error === 'string') return error;
    if (Array.isArray(error)) {
        return error
            .map((e) => (typeof e === 'object' && e !== null ? e.msg || JSON.stringify(e) : String(e)))
            .join(' | ');
    }
    if (typeof error === 'object') {
        return error.msg || error.detail || error.error_message || error.error || JSON.stringify(error);
    }
    return String(error);
};

// Covers the backend's own wording plus the shapes a bare exec failure takes
// ("[Errno 2] No such file or directory: 'nmap'", "nmap: command not found").
const NMAP_MISSING = /nmap is not installed|nmap.*not in\s*path|no such file[^\n]*nmap|nmap:?\s*(command )?not found/i;

export const isNmapMissing = (error) => NMAP_MISSING.test(errorToText(error));

export const NMAP_INSTALL_COMMAND = 'sudo apt-get install -y nmap';

/** Persian, RTL. The shell command stays LTR inside its own element. */
export const NmapMissingNotice = () => (
    <div className="nmap-missing" dir="rtl">
        <strong className="nmap-missing-title">nmap روی سرور نصب نیست</strong>
        <span className="nmap-missing-hint">
            برای فعال شدن اسکن شبکه، دستور زیر را روی سرور اجرا کنید:
        </span>
        <code className="nmap-missing-cmd" dir="ltr">{NMAP_INSTALL_COMMAND}</code>
    </div>
);

const WarningIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        <path d="M12 9v4M12 17h.01" />
    </svg>
);

const ErrorIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <path d="M15 9l-6 6M9 9l6 6" />
    </svg>
);

/**
 * Renders a scan failure as an alert — a warning with install instructions when
 * nmap is missing, the plain error otherwise. Returns null when there is no
 * error, so callers can render it unconditionally.
 */
export const ScanErrorAlert = ({ error, onClose }) => {
    const text = errorToText(error);
    if (!text) return null;

    const missing = isNmapMissing(text);

    return (
        <div className={`alert ${missing ? 'alert-warning' : 'alert-error'}`}>
            {missing ? <WarningIcon /> : <ErrorIcon />}
            {missing ? <NmapMissingNotice /> : <span>{text}</span>}
            {onClose && (
                <button className="alert-close" onClick={onClose} type="button" aria-label="Dismiss">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                </button>
            )}
        </div>
    );
};

export default ScanErrorAlert;
