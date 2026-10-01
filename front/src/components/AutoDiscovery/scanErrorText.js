// Plain helpers for scan errors, kept apart from the components in
// scanErrors.jsx (a component file should export only components).

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
