import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditSessions, getDeviceName } from "../../store/hardeningSlice";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const isLinux    = (dt) => dt === "linux" || dt?.startsWith("linux-");
const isCisco    = (dt) => dt === "cisco";
const isFortinet = (dt) => dt === "fortinet";
const isApache   = (dt) => dt === "apache";
const isMongo    = (dt) => dt === "mongodb";
const isMssql    = (dt) => dt?.startsWith("mssql-");
const isWindows  = (dt) => dt?.startsWith("windows-");

const needsSudo  = (dt) => isLinux(dt) || isApache(dt) || isMongo(dt);

// ─── Component ────────────────────────────────────────────────────────────────

export const FixUnsuccessfulConnectionForm = ({ onSubmit, onCancel }) => {
    const dispatch = useDispatch();
    const { auditSessions, isLoading } = useSelector((state) => state.hardening);

    const [formData, setFormData] = useState({
        session_id:       "",
        // SSH-based
        ssh_username:     "",
        ssh_password:     "",
        ssh_port:         "22",
        ssh_secret:       "",     // Cisco
        vdom:             "",     // Fortinet
        sudo_password:    "",     // Linux / Apache / MongoDB
        // MongoDB extra
        mongo_username:   "",
        mongo_password:   "",
        mongo_port:       "27017",
        // MSSQL
        mssql_username:   "",
        mssql_password:   "",
        mssql_port:       "1433",
        // Windows
        windows_username: "",
        windows_password: "",
        winrm_port:       "5986",
        transport:        "ntlm",
    });

    const [selectedSession, setSelectedSession] = useState(null);
    const [deviceType, setDeviceType]           = useState(null);
    const [errors, setErrors]                   = useState({});

    useEffect(() => {
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    // Only sessions that are completed AND have failed checks
    const failedAuditSessions = (auditSessions || []).filter(
        (session) =>
            session.status === "completed" &&
            (
                (session.compliance?.failed_checks > 0) ||
                (session.compliance?.failed > 0)
            )
    );

    const getFailedCount = (session) =>
        session?.compliance?.failed_checks ||
        session?.compliance?.failed ||
        0;

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        if (name === "session_id") {
            if (value) {
                const session = failedAuditSessions.find(
                    (s) => s.session_id === parseInt(value)
                );
                setSelectedSession(session || null);
                setDeviceType(session?.sub_device_type || session?.device_type || null);
            } else {
                setSelectedSession(null);
                setDeviceType(null);
            }
        }

        if (errors[name]) {
            setErrors((prev) => { const n = { ...prev }; delete n[name]; return n; });
        }
    };

    const validate = () => {
        const errs = {};

        if (!formData.session_id) errs.session_id = "Please select an audit job";

        if (isWindows(deviceType)) {
            if (!formData.windows_username?.trim()) errs.windows_username = "Username is required";
            if (!formData.windows_password?.trim()) errs.windows_password = "Password is required";
        } else if (isMssql(deviceType)) {
            if (!formData.mssql_username?.trim()) errs.mssql_username = "Username is required";
            if (!formData.mssql_password?.trim()) errs.mssql_password = "Password is required";
        } else {
            if (!formData.ssh_username?.trim()) errs.ssh_username = "Username is required";
            if (!formData.ssh_password?.trim()) errs.ssh_password = "Password is required";
        }

        setErrors(errs);
        return Object.keys(errs).length === 0;
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!validate()) return;

        const sessionId = parseInt(formData.session_id);
        if (isNaN(sessionId) || !selectedSession) {
            setErrors({ session_id: "Please select a valid audit job" });
            return;
        }

        // Build credentials
        let credentials = {};

        if (isWindows(deviceType)) {
            credentials = {
                windows_username: formData.windows_username,
                windows_password: formData.windows_password,
                winrm_port:       parseInt(formData.winrm_port) || 5986,
                transport:        formData.transport || "ntlm",
            };
        } else if (isMssql(deviceType)) {
            credentials = {
                mssql_username: formData.mssql_username,
                mssql_password: formData.mssql_password,
                mssql_port:     parseInt(formData.mssql_port) || 1433,
            };
        } else {
            credentials = {
                ssh_username: formData.ssh_username,
                ssh_password: formData.ssh_password,
                ssh_port:     parseInt(formData.ssh_port) || 22,
                ...(isCisco(deviceType)   && formData.ssh_secret     && { ssh_secret:    formData.ssh_secret }),
                ...(isFortinet(deviceType) && formData.vdom           && { vdom:          formData.vdom }),
                ...(needsSudo(deviceType)  && formData.sudo_password  && { sudo_password: formData.sudo_password }),
                ...(isMongo(deviceType)    && formData.mongo_username && { mongo_username: formData.mongo_username }),
                ...(isMongo(deviceType)    && formData.mongo_password && { mongo_password: formData.mongo_password }),
                ...(isMongo(deviceType)    && { mongo_port: parseInt(formData.mongo_port) || 27017 }),
            };
        }

        onSubmit({
            session_id: sessionId,
            session: { ...selectedSession, device_type: deviceType },
            device_type: deviceType,
            credentials,
        });
    };

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Audit Job Dropdown ───────────────────────────────── */}
                    <div className="form-group form-group-full">
                        <label htmlFor="session_id">
                            Audit Job Name
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>

                        {isLoading ? (
                            <div style={{
                                padding: "10px 14px",
                                background: "#f8f9fa",
                                border: "1px solid #d1d5db",
                                borderRadius: "6px",
                                fontSize: "13px",
                                color: "#6b7280",
                            }}>
                                Loading sessions…
                            </div>
                        ) : (
                            <select
                                id="session_id"
                                name="session_id"
                                value={formData.session_id}
                                onChange={handleChange}
                                className={errors.session_id ? "error" : ""}
                            >
                                <option value="">Select an audit job</option>
                                {failedAuditSessions.map((session) => (
                                    <option key={session.session_id} value={session.session_id}>
                                        {session.job_name || session.asset_name} | {session.target_ip} —{" "}
                                        {session.completed_at
                                            ? new Date(session.completed_at).toLocaleDateString()
                                            : session.started_at
                                                ? new Date(session.started_at).toLocaleDateString()
                                                : "N/A"
                                        }{" "}
                                        ({getFailedCount(session)} Failed)
                                    </option>
                                ))}
                            </select>
                        )}

                        {errors.session_id && (
                            <span className="error-message">{errors.session_id}</span>
                        )}

                        {!isLoading && failedAuditSessions.length === 0 && (
                            <div style={{
                                marginTop: "10px",
                                padding: "14px 16px",
                                background: "#fef3c7",
                                border: "1px solid #f59e0b",
                                borderRadius: "8px",
                            }}>
                                <p style={{ margin: "0 0 4px 0", fontWeight: "600", fontSize: "13px", color: "#92400e" }}>
                                    ⚠️ No failed audit sessions found
                                </p>
                                <p style={{ margin: 0, fontSize: "12px", color: "#78350f" }}>
                                    Please run an audit first. Only completed audits with failed checks appear here.
                                </p>
                            </div>
                        )}
                    </div>

                    {/* ── Session Info Box ─────────────────────────────────── */}
                    {selectedSession && (
                        <div className="form-group form-group-full" style={{
                            background: "#eff6ff",
                            borderLeft: "4px solid #3b82f6",
                            padding: "12px 16px",
                            borderRadius: "6px",
                        }}>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>Asset:</strong> {selectedSession.asset_name || "N/A"}
                            </p>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>IP Address:</strong> {selectedSession.target_ip || "N/A"}
                            </p>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>Device Type:</strong> {getDeviceName(deviceType)}
                            </p>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>Status:</strong> {selectedSession.status}
                            </p>
                            {selectedSession.compliance && (
                                <>
                                    <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                        <strong>Total Checks:</strong>{" "}
                                        {selectedSession.compliance.total_checks || selectedSession.compliance.total || 0}
                                    </p>
                                    <p style={{ margin: "4px 0", fontSize: "13px", color: "#dc2626" }}>
                                        <strong>Failed Checks:</strong> {getFailedCount(selectedSession)}
                                    </p>
                                    <p style={{ margin: "4px 0", fontSize: "13px", color: "#059669" }}>
                                        <strong>Passed Checks:</strong>{" "}
                                        {selectedSession.compliance.passed_checks || selectedSession.compliance.passed || 0}
                                    </p>
                                </>
                            )}
                        </div>
                    )}

                    {/* ══════════════════════════════════════════════════════
                        SSH-based credentials
                    ══════════════════════════════════════════════════════ */}
                    {deviceType && !isWindows(deviceType) && !isMssql(deviceType) && (
                        <>
                            <div className="form-group">
                                <label htmlFor="ssh_username">
                                    SSH Username
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    id="ssh_username"
                                    type="text"
                                    name="ssh_username"
                                    value={formData.ssh_username}
                                    onChange={handleChange}
                                    placeholder="Enter SSH username"
                                    className={errors.ssh_username ? "error" : ""}
                                    autoComplete="username"
                                />
                                {errors.ssh_username && (
                                    <span className="error-message">{errors.ssh_username}</span>
                                )}
                            </div>

                            {/* Cisco */}
                            {isCisco(deviceType) && (
                                <div className="form-group">
                                    <label htmlFor="ssh_secret">Enable Password</label>
                                    <input
                                        id="ssh_secret"
                                        type="password"
                                        name="ssh_secret"
                                        value={formData.ssh_secret}
                                        onChange={handleChange}
                                        placeholder="Enable secret (optional)"
                                        autoComplete="off"
                                    />
                                    <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                        Required for privileged commands
                                    </span>
                                </div>
                            )}

                            {/* Fortinet */}
                            {isFortinet(deviceType) && (
                                <div className="form-group">
                                    <label htmlFor="vdom">VDOM</label>
                                    <input
                                        id="vdom"
                                        type="text"
                                        name="vdom"
                                        value={formData.vdom}
                                        onChange={handleChange}
                                        placeholder="Virtual Domain (optional, default: root)"
                                        autoComplete="off"
                                    />
                                    <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                        Leave empty for default VDOM
                                    </span>
                                </div>
                            )}

                            {/* Linux / Apache / MongoDB: Sudo */}
                            {needsSudo(deviceType) && (
                                <div className="form-group">
                                    <label htmlFor="sudo_password">Sudo Password</label>
                                    <input
                                        id="sudo_password"
                                        type="password"
                                        name="sudo_password"
                                        value={formData.sudo_password}
                                        onChange={handleChange}
                                        placeholder="Sudo password (optional)"
                                        autoComplete="off"
                                    />
                                    <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                        Defaults to SSH password if empty
                                    </span>
                                </div>
                            )}

                            {/* MongoDB extra */}
                            {isMongo(deviceType) && (
                                <>
                                    <div className="form-group">
                                        <label>MongoDB Username</label>
                                        <input
                                            type="text"
                                            name="mongo_username"
                                            value={formData.mongo_username}
                                            onChange={handleChange}
                                            placeholder="admin (optional)"
                                            autoComplete="off"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>MongoDB Password</label>
                                        <input
                                            type="password"
                                            name="mongo_password"
                                            value={formData.mongo_password}
                                            onChange={handleChange}
                                            placeholder="MongoDB password (optional)"
                                            autoComplete="off"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>MongoDB Port</label>
                                        <input
                                            type="number"
                                            name="mongo_port"
                                            value={formData.mongo_port}
                                            onChange={handleChange}
                                            placeholder="27017"
                                            autoComplete="off"
                                        />
                                    </div>
                                </>
                            )}

                            {/* SSH Password */}
                            <div className="form-group form-group-full">
                                <label htmlFor="ssh_password">
                                    SSH Password
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    id="ssh_password"
                                    type="password"
                                    name="ssh_password"
                                    value={formData.ssh_password}
                                    onChange={handleChange}
                                    placeholder="Enter SSH password"
                                    className={errors.ssh_password ? "error" : ""}
                                    autoComplete="current-password"
                                />
                                {errors.ssh_password && (
                                    <span className="error-message">{errors.ssh_password}</span>
                                )}
                            </div>

                            {/* SSH Port */}
                            <div className="form-group">
                                <label htmlFor="ssh_port">SSH Port</label>
                                <input
                                    id="ssh_port"
                                    type="number"
                                    name="ssh_port"
                                    value={formData.ssh_port}
                                    onChange={handleChange}
                                    placeholder="22"
                                    min="1"
                                    max="65535"
                                    autoComplete="off"
                                />
                            </div>
                        </>
                    )}

                    {/* ══════════════════════════════════════════════════════
                        MSSQL credentials
                    ══════════════════════════════════════════════════════ */}
                    {deviceType && isMssql(deviceType) && (
                        <>
                            <div className="form-group">
                                <label>
                                    SQL Server Username
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="mssql_username"
                                    value={formData.mssql_username}
                                    onChange={handleChange}
                                    className={errors.mssql_username ? "error" : ""}
                                    placeholder="sa or sysadmin account"
                                    autoComplete="username"
                                />
                                {errors.mssql_username && (
                                    <span className="error-message">{errors.mssql_username}</span>
                                )}
                            </div>
                            <div className="form-group">
                                <label>SQL Server Port</label>
                                <input
                                    type="number"
                                    name="mssql_port"
                                    value={formData.mssql_port}
                                    onChange={handleChange}
                                    placeholder="1433"
                                />
                            </div>
                            <div className="form-group form-group-full">
                                <label>
                                    SQL Server Password
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="mssql_password"
                                    value={formData.mssql_password}
                                    onChange={handleChange}
                                    className={errors.mssql_password ? "error" : ""}
                                    placeholder="SQL Server password"
                                    autoComplete="current-password"
                                />
                                {errors.mssql_password && (
                                    <span className="error-message">{errors.mssql_password}</span>
                                )}
                            </div>
                        </>
                    )}

                    {/* ══════════════════════════════════════════════════════
                        Windows credentials
                    ══════════════════════════════════════════════════════ */}
                    {deviceType && isWindows(deviceType) && (
                        <>
                            <div className="form-group">
                                <label>
                                    Windows Username
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="windows_username"
                                    value={formData.windows_username}
                                    onChange={handleChange}
                                    className={errors.windows_username ? "error" : ""}
                                    placeholder="Administrator or DOMAIN\user"
                                    autoComplete="username"
                                />
                                {errors.windows_username && (
                                    <span className="error-message">{errors.windows_username}</span>
                                )}
                            </div>
                            <div className="form-group">
                                <label>WinRM Port</label>
                                <input
                                    type="number"
                                    name="winrm_port"
                                    value={formData.winrm_port}
                                    onChange={handleChange}
                                    placeholder="5986"
                                />
                                <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                    Default: 5986 (HTTPS)
                                </span>
                            </div>
                            <div className="form-group">
                                <label>Transport</label>
                                <select name="transport" value={formData.transport} onChange={handleChange}>
                                    <option value="ntlm">NTLM</option>
                                    <option value="kerberos">Kerberos</option>
                                    <option value="credssp">CredSSP</option>
                                    <option value="basic">Basic</option>
                                </select>
                            </div>
                            <div className="form-group form-group-full">
                                <label>
                                    Windows Password
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="windows_password"
                                    value={formData.windows_password}
                                    onChange={handleChange}
                                    className={errors.windows_password ? "error" : ""}
                                    placeholder="Windows admin password"
                                    autoComplete="current-password"
                                />
                                {errors.windows_password && (
                                    <span className="error-message">{errors.windows_password}</span>
                                )}
                            </div>
                        </>
                    )}

                </div>

                {/* Actions */}
                <div className="form-actions">
                    <button
                        type="button"
                        onClick={onCancel}
                        className="btn-cancel"
                        disabled={isLoading}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        className="btn-see-result"
                        disabled={isLoading || failedAuditSessions.length === 0}
                    >
                        Next
                    </button>
                </div>
            </form>
        </div>
    );
};

export default FixUnsuccessfulConnectionForm;