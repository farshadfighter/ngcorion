// Shared helpers for hardening credentials, used by HardenAllModal and
// FixSingleModal (and anywhere else that collects device credentials for a
// hardening run). Keeping the device-type predicates, the credential state
// shape, validation, and the request-payload builder in one place avoids the
// drift that previously let the two modals diverge (e.g. VDOM handling).

// ─── Device type predicates ─────────────────────────────────────────────────
export const isLinux    = (dt) => dt === "linux" || dt?.startsWith("linux-");
export const isCisco    = (dt) => dt === "cisco";
export const isFortinet = (dt) => dt === "fortinet";
export const isApache   = (dt) => dt === "apache";
export const isMongo    = (dt) => dt === "mongodb";
export const isMssql    = (dt) => dt?.startsWith("mssql-");
export const isWindows  = (dt) => dt?.startsWith("windows-");
export const needsSudo  = (dt) => isLinux(dt) || isApache(dt) || isMongo(dt);

// ─── Default form state ──────────────────────────────────────────────────────
export const defaultCredentialsState = {
    // SSH-based (Linux, Cisco, Fortinet, Apache, MongoDB)
    ssh_username:     "",
    ssh_password:     "",
    ssh_port:         "22",
    ssh_secret:       "",       // Cisco only
    vdom:             "",       // Fortinet only
    sudo_password:    "",       // Linux / Apache / MongoDB
    // MongoDB extra
    mongo_username:   "",
    mongo_password:   "",
    mongo_port:       "27017",
    // MSSQL
    mssql_username:   "",
    mssql_password:   "",
    mssql_port:       "1433",
    // Windows (WinRM)
    windows_username: "",
    windows_password: "",
    winrm_port:       "5986",
    transport:        "ntlm",
};

// ─── Validation ──────────────────────────────────────────────────────────────
// Returns a { fieldName: message } object. Empty object means valid.
export function validateCredentials(deviceType, creds) {
    const errors = {};
    if (isWindows(deviceType)) {
        if (!creds.windows_username?.trim()) errors.windows_username = "Windows Username is required";
        if (!creds.windows_password?.trim()) errors.windows_password = "Windows Password is required";
    } else if (isMssql(deviceType)) {
        if (!creds.mssql_username?.trim()) errors.mssql_username = "SQL Server Username is required";
        if (!creds.mssql_password?.trim()) errors.mssql_password = "SQL Server Password is required";
    } else {
        if (!creds.ssh_username?.trim()) errors.ssh_username = "SSH Username is required";
        if (!creds.ssh_password?.trim()) errors.ssh_password = "SSH Password is required";
    }
    return errors;
}

// ─── Request payload builder ─────────────────────────────────────────────────
// Builds the credentials object sent to the hardening execute endpoints.
export function buildCredentials(deviceType, creds, { vdomEnabled = false } = {}) {
    if (isWindows(deviceType)) {
        return {
            windows_username: creds.windows_username,
            windows_password: creds.windows_password,
            winrm_port:       parseInt(creds.winrm_port) || 5986,
            transport:        creds.transport || "ntlm",
        };
    }
    if (isMssql(deviceType)) {
        return {
            mssql_username: creds.mssql_username,
            mssql_password: creds.mssql_password,
            mssql_port:     parseInt(creds.mssql_port) || 1433,
        };
    }
    return {
        ssh_username: creds.ssh_username,
        ssh_password: creds.ssh_password,
        ssh_port:     parseInt(creds.ssh_port) || 22,
        ...(isCisco(deviceType)    && creds.ssh_secret    && { ssh_secret:     creds.ssh_secret }),
        ...(isFortinet(deviceType) && vdomEnabled && creds.vdom && { vdom:      creds.vdom }),
        ...(needsSudo(deviceType)  && creds.sudo_password && { sudo_password:  creds.sudo_password }),
        ...(isMongo(deviceType)    && creds.mongo_username && { mongo_username: creds.mongo_username }),
        ...(isMongo(deviceType)    && creds.mongo_password && { mongo_password: creds.mongo_password }),
        ...(isMongo(deviceType)    && { mongo_port: parseInt(creds.mongo_port) || 27017 }),
    };
}
