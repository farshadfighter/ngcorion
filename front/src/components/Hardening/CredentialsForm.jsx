import {
    isWindows,
    isMssql,
    isCisco,
    isFortinet,
    isMongo,
    needsSudo,
} from "./hardeningCredentials";

// Shared credentials form used by HardenAllModal and FixSingleModal.
//
// Props:
//   deviceType            - device type string (drives which fields show)
//   value                 - credentials state object (see defaultCredentialsState)
//   onChange              - (e) => void, standard input change handler
//   errors                - { fieldName: message } map for inline validation
//   vdomEnabled           - bool, Fortinet "uses VDOMs" toggle
//   onVdomEnabledChange   - (bool) => void
//   vdomDiscovery         - redux vdomDiscovery slice ({ isDiscovering, vdoms, error })
//   onDetectVdoms         - () => void, triggers VDOM discovery
//   canDetectVdoms        - bool, whether discovery prerequisites are met

const inputStyle = {
    width: "450px",
    padding: "8px 12px",
    border: "1px solid #d1d5db",
    borderRadius: "6px",
    fontSize: "13px",
    color: "#111827",
    transition: "all 0.2s",
    background: "white",
};
const hintStyle = { fontSize: "12px", color: "#7f8c8d", display: "block", marginTop: "4px" };
const errorStyle = { fontSize: "12px", color: "#dc2626", display: "block", marginTop: "4px" };

const FieldError = ({ message }) => (message ? <span style={errorStyle}>{message}</span> : null);

export default function CredentialsForm({
    deviceType,
    value,
    onChange,
    errors = {},
    vdomEnabled = false,
    onVdomEnabledChange,
    vdomDiscovery,
    onDetectVdoms,
    canDetectVdoms = false,
}) {
    // ── Windows ──────────────────────────────────────────────────────────────
    if (isWindows(deviceType)) {
        return (
            <div className="hardening-ssh-form">
                <div className="hardening-form-group">
                    <label>Windows Username<span className="hardening-required">*</span></label>
                    <input type="text" name="windows_username" value={value.windows_username} onChange={onChange} placeholder="Administrator or DOMAIN\user" autoComplete="username" style={inputStyle} />
                    <FieldError message={errors.windows_username} />
                </div>
                <div className="hardening-form-group">
                    <label>Windows Password<span className="hardening-required">*</span></label>
                    <input type="password" name="windows_password" value={value.windows_password} onChange={onChange} placeholder="Windows admin password" autoComplete="current-password" style={inputStyle} />
                    <FieldError message={errors.windows_password} />
                </div>
                <div className="hardening-form-group">
                    <label>WinRM Port</label>
                    <input type="number" name="winrm_port" value={value.winrm_port} onChange={onChange} placeholder="5986" autoComplete="off" style={inputStyle} />
                    <span style={hintStyle}>Default: 5986 (HTTPS)</span>
                </div>
                <div className="hardening-form-group">
                    <label>Transport</label>
                    <select name="transport" value={value.transport} onChange={onChange} style={inputStyle}>
                        <option value="ntlm">NTLM</option>
                        <option value="kerberos">Kerberos</option>
                        <option value="credssp">CredSSP</option>
                        <option value="basic">Basic</option>
                    </select>
                </div>
            </div>
        );
    }

    // ── MSSQL ────────────────────────────────────────────────────────────────
    if (isMssql(deviceType)) {
        return (
            <div className="hardening-ssh-form">
                <div className="hardening-form-group">
                    <label>SQL Server Username<span className="hardening-required">*</span></label>
                    <input type="text" name="mssql_username" value={value.mssql_username} onChange={onChange} placeholder="sa or sysadmin account" autoComplete="username" style={inputStyle} />
                    <FieldError message={errors.mssql_username} />
                </div>
                <div className="hardening-form-group">
                    <label>SQL Server Password<span className="hardening-required">*</span></label>
                    <input type="password" name="mssql_password" value={value.mssql_password} onChange={onChange} placeholder="SQL Server password" autoComplete="current-password" style={inputStyle} />
                    <FieldError message={errors.mssql_password} />
                </div>
                <div className="hardening-form-group">
                    <label>SQL Server Port</label>
                    <input type="number" name="mssql_port" value={value.mssql_port} onChange={onChange} placeholder="1433" autoComplete="off" style={inputStyle} />
                </div>
            </div>
        );
    }

    // ── SSH-based: Linux, Cisco, Fortinet, Apache, MongoDB ───────────────────
    return (
        <div className="hardening-ssh-form">
            <div className="hardening-form-group">
                <label>SSH Username<span className="hardening-required">*</span></label>
                <input type="text" name="ssh_username" value={value.ssh_username} onChange={onChange} placeholder="Enter SSH username" autoComplete="username" style={inputStyle} />
                <FieldError message={errors.ssh_username} />
            </div>
            <div className="hardening-form-group">
                <label>SSH Password<span className="hardening-required">*</span></label>
                <input type="password" name="ssh_password" value={value.ssh_password} onChange={onChange} placeholder="Enter SSH password" autoComplete="current-password" style={inputStyle} />
                <FieldError message={errors.ssh_password} />
            </div>
            <div className="hardening-form-group">
                <label>SSH Port</label>
                <input type="number" name="ssh_port" value={value.ssh_port} onChange={onChange} placeholder="22" min="1" max="65535" autoComplete="off" style={inputStyle} />
            </div>

            {/* Cisco: Enable Secret */}
            {isCisco(deviceType) && (
                <div className="hardening-form-group">
                    <label>Enable Password</label>
                    <input type="password" name="ssh_secret" value={value.ssh_secret} onChange={onChange} placeholder="Enter enable secret (optional)" autoComplete="off" style={inputStyle} />
                    <span style={hintStyle}>Required for privileged commands</span>
                </div>
            )}

            {/* Fortinet: VDOM discovery */}
            {isFortinet(deviceType) && (
                <div className="hardening-form-group">
                    <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer" }}>
                        <input
                            type="checkbox"
                            checked={vdomEnabled}
                            onChange={(e) => onVdomEnabledChange?.(e.target.checked)}
                            style={{ width: "16px", height: "16px", cursor: "pointer" }}
                        />
                        This FortiGate uses VDOMs
                    </label>

                    {vdomEnabled && (
                        <div style={{ marginTop: "8px" }}>
                            <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "6px" }}>
                                <button
                                    type="button"
                                    onClick={onDetectVdoms}
                                    disabled={vdomDiscovery?.isDiscovering || !canDetectVdoms}
                                    style={{
                                        padding: "6px 14px", fontSize: "13px", fontWeight: 600,
                                        background: "#2563eb", color: "white", border: "none",
                                        borderRadius: "6px", cursor: "pointer",
                                        opacity: (vdomDiscovery?.isDiscovering || !canDetectVdoms) ? 0.5 : 1,
                                    }}
                                >
                                    {vdomDiscovery?.isDiscovering ? "Detecting…" : "Show VDOMs"}
                                </button>
                                {vdomDiscovery?.vdoms !== null && vdomDiscovery?.vdoms !== undefined && !vdomDiscovery?.isDiscovering && (
                                    <span style={{
                                        padding: "3px 10px", borderRadius: "12px", fontSize: "12px", fontWeight: 600,
                                        background: vdomDiscovery.vdoms.length > 0 ? "#d1fae5" : "#f3f4f6",
                                        color: vdomDiscovery.vdoms.length > 0 ? "#065f46" : "#6b7280",
                                        border: `1px solid ${vdomDiscovery.vdoms.length > 0 ? "#6ee7b7" : "#d1d5db"}`,
                                    }}>
                                        {vdomDiscovery.vdoms.length > 0
                                            ? `✓ VDOM Enabled (${vdomDiscovery.vdoms.length})`
                                            : "No VDOMs found"}
                                    </span>
                                )}
                            </div>
                            {vdomDiscovery?.error && (
                                <span style={{ fontSize: "12px", color: "#dc2626", display: "block", marginBottom: "4px" }}>
                                    {vdomDiscovery.error}
                                </span>
                            )}
                            {vdomDiscovery?.vdoms?.length > 0 ? (
                                <select name="vdom" value={value.vdom} onChange={onChange} style={inputStyle}>
                                    <option value="">Select VDOM (default: root)</option>
                                    {vdomDiscovery.vdoms.map((v) => (
                                        <option key={v} value={v}>{v}</option>
                                    ))}
                                </select>
                            ) : (
                                <input type="text" name="vdom" value={value.vdom} onChange={onChange} placeholder="VDOM name (e.g. root)" autoComplete="off" style={inputStyle} />
                            )}
                            <span style={hintStyle}>Click "Show VDOMs" to list virtual domains, then pick the target VDOM.</span>
                        </div>
                    )}
                </div>
            )}

            {/* Linux / Apache / MongoDB: Sudo Password */}
            {needsSudo(deviceType) && (
                <div className="hardening-form-group">
                    <label>Sudo Password</label>
                    <input type="password" name="sudo_password" value={value.sudo_password} onChange={onChange} placeholder="Sudo password (optional)" autoComplete="off" style={inputStyle} />
                    <span style={hintStyle}>Required for root access (defaults to SSH password)</span>
                </div>
            )}

            {/* MongoDB: extra DB credentials */}
            {isMongo(deviceType) && (
                <>
                    <div className="hardening-form-group">
                        <label>MongoDB Username</label>
                        <input type="text" name="mongo_username" value={value.mongo_username} onChange={onChange} placeholder="admin (optional)" autoComplete="off" style={inputStyle} />
                    </div>
                    <div className="hardening-form-group">
                        <label>MongoDB Password</label>
                        <input type="password" name="mongo_password" value={value.mongo_password} onChange={onChange} placeholder="MongoDB password (optional)" autoComplete="off" style={inputStyle} />
                    </div>
                    <div className="hardening-form-group">
                        <label>MongoDB Port</label>
                        <input type="number" name="mongo_port" value={value.mongo_port} onChange={onChange} placeholder="27017" autoComplete="off" style={inputStyle} />
                    </div>
                </>
            )}
        </div>
    );
}
