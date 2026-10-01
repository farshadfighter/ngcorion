import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import TargetPicker from "../shared/TargetPicker.jsx";
import { executeAuditWithDevice, discoverFortinetVdoms, clearVdomDiscovery } from "../../store/hardeningSlice";
import { DEFAULT_WINRM_PORT } from "./winrmDefaults";
import {
    isCisco,
    isFortinet,
    isMongo,
    isMssql,
    isWindows,
    needsSudo,
} from "./hardeningCredentials";

// ─── Helpers ──────────────────────────────────────────────────────────────────
// The device-type predicates come from hardeningCredentials.js. They used to be
// copied here, and the copies only matched the prefixed form ("windows-2022"),
// so they silently disagreed with the shared ones once those learned to accept
// the bare enum too — the same drift that had the single-check modal asking a
// Windows Server for SSH credentials. One definition, no drift.
const needsVdom  = (dt) => isFortinet(dt);
const needsSecret= (dt) => isCisco(dt);

// ─── Component ────────────────────────────────────────────────────────────────
export const HardeningConnectionForm = ({ onSubmit, onCancel }) => {
    const dispatch = useDispatch();
    const { isLoading } = useSelector((state) => state.hardening);
    const vdomDiscovery = useSelector((state) => state.hardening.vdomDiscovery);

    // The picker owns the asset list; the form only keeps the chosen asset.
    const [selectedAsset, setSelectedAsset] = useState(null);

    const [formData, setFormData] = useState({
        device_type:      "", // chosen by the target picker
        asset_id:         "",
        job_name:         "",
        ssh_username:     "",
        ssh_password:     "",
        ssh_port:         "22",
        ssh_secret:       "",
        vdom:             "",
        sudo_password:    "",
        mongo_username:   "",
        mongo_password:   "",
        mongo_port:       "27017",
        mssql_username:   "",
        mssql_password:   "",
        mssql_port:       "1433",
        windows_username: "",
        windows_password: "",
        winrm_port:       DEFAULT_WINRM_PORT,
        transport:        "ntlm",
    });

    const [errors, setErrors] = useState({});

    useEffect(() => {
        dispatch(clearVdomDiscovery());
    }, [dispatch]);

    const dt = formData.device_type;


    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value,
        }));
        if (errors[name]) {
            setErrors((prev) => { const n = { ...prev }; delete n[name]; return n; });
        }
    };

    // From the target picker: device_type and/or asset_id, plus the asset.
    const handleTargetChange = (patch, asset) => {
        setFormData((prev) => ({ ...prev, ...patch, vdom: "" }));
        setSelectedAsset(asset || null);
        // Discovered VDOMs are asset/device-specific - drop them on any change.
        dispatch(clearVdomDiscovery());
        setErrors((prev) => {
            const n = { ...prev };
            Object.keys(patch).forEach((k) => delete n[k]);
            return n;
        });
    };

    const handleDetectVdoms = () => {
        const errs = {};
        if (!formData.asset_id) errs.asset_id = "Please select an asset";
        if (!formData.ssh_username?.trim()) errs.ssh_username = "Username is required";
        if (!formData.ssh_password?.trim()) errs.ssh_password = "Password is required";
        if (Object.keys(errs).length) { setErrors(errs); return; }

        dispatch(discoverFortinetVdoms({
            asset_id:     parseInt(formData.asset_id),
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
            ssh_port:     parseInt(formData.ssh_port) || 22,
            mode:         "hardening",
        }));
    };

    const validate = () => {
        const errs = {};

        if (!formData.device_type) {
            errs.device_type = "Choose what to harden";
        }
        if (!formData.asset_id) {
            errs.asset_id = "Please select an asset";
        }
        if (!formData.job_name || formData.job_name.trim().length < 2) {
            errs.job_name = "Job name must be at least 2 characters";
        }

        if (isWindows(dt)) {
            if (!formData.windows_username?.trim()) errs.windows_username = "Username is required";
            if (!formData.windows_password?.trim()) errs.windows_password = "Password is required";
        } else if (isMssql(dt)) {
            if (!formData.mssql_username?.trim()) errs.mssql_username = "Username is required";
            if (!formData.mssql_password?.trim()) errs.mssql_password = "Password is required";
        } else {
            if (!formData.ssh_username?.trim()) errs.ssh_username = "Username is required";
            if (!formData.ssh_password?.trim()) errs.ssh_password = "Password is required";
        }

        setErrors(errs);
        return Object.keys(errs).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!validate()) return;

        const assetId = parseInt(formData.asset_id);
        if (isNaN(assetId)) {
            setErrors({ asset_id: "Please select a valid asset" });
            return;
        }

        let credentials = {};

        if (isWindows(dt)) {
            credentials = {
                windows_username: formData.windows_username,
                windows_password: formData.windows_password,
                winrm_port:       parseInt(formData.winrm_port) || Number(DEFAULT_WINRM_PORT),
                transport:        formData.transport || "ntlm",
            };
        } else if (isMssql(dt)) {
            credentials = {
                mssql_username: formData.mssql_username,
                mssql_password: formData.mssql_password,
                mssql_port:     parseInt(formData.mssql_port) || 1433,
            };
        } else {
            credentials = {
                ssh_username: formData.ssh_username,
                ssh_password: formData.ssh_password,
                // Every SSH-based family accepts ssh_port — sending it only for
                // Fortinet made non-22 Linux/Cisco/Apache/Mongo hosts unreachable.
                ssh_port: parseInt(formData.ssh_port) || 22,
                ...(isCisco(dt)    && formData.ssh_secret    && { ssh_secret:    formData.ssh_secret }),
                ...(isFortinet(dt) && formData.vdom          && { vdom:          formData.vdom }),
                ...(needsSudo(dt)  && formData.sudo_password && { sudo_password: formData.sudo_password }),
                ...(isMongo(dt)    && formData.mongo_username && { mongo_username: formData.mongo_username }),
                ...(isMongo(dt)    && formData.mongo_password && { mongo_password: formData.mongo_password }),
                ...(isMongo(dt)    && { mongo_port: parseInt(formData.mongo_port) || 27017 }),
            };
        }

        const tempSessionData = {
            session_id:  "pending",
            asset_name:  selectedAsset?.asset_name || "N/A",
            target_ip:   selectedAsset?.ip_address || "N/A",
            device_type: dt,
            status:      "pending",
        };
        onSubmit(tempSessionData);

        try {
            const result = await dispatch(
                executeAuditWithDevice({
                    deviceType: dt,
                    assetId,
                    credentials,
                    jobName: formData.job_name,
                })
            ).unwrap();
            onSubmit(result);
        } catch (err) {
            // Extract error message from various possible formats
            let msg = "Failed to connect — please check your credentials and try again.";

            if (typeof err === "string") {
                msg = err;
            } else if (err?.detail) {
                msg = err.detail;
            } else if (err?.message) {
                msg = err.message;
            } else if (err?.toString && err.toString() !== "[object Object]") {
                msg = err.toString();
            }

            setErrors({ submit: msg });
        }
    };


    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Target + asset (spans both columns) ── */}
                    <div className="form-group form-group-full" style={{ gridColumn: "1 / -1" }}>
                        <TargetPicker
                            mode="hardening"
                            deviceType={formData.device_type}
                            assetId={formData.asset_id}
                            onChange={handleTargetChange}
                            errors={errors}
                        />
                    </div>

                    {/* ── Job Name ── */}
                    <div className="form-group">
                        <label>
                            Job Name
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>
                        <input
                            type="text"
                            name="job_name"
                            value={formData.job_name}
                            onChange={handleChange}
                            className={errors.job_name ? "error" : ""}
                            placeholder="Enter job name"
                            autoComplete="off"
                        />
                        {errors.job_name && <span className="error-message">{errors.job_name}</span>}
                    </div>

                    {/* ══════════════════════════════════════════════════════
                        SSH credentials (Linux, Cisco, Fortinet, Apache, MongoDB)
                    ══════════════════════════════════════════════════════ */}
                    {!isWindows(dt) && !isMssql(dt) && (
                        <>
                            <div className="form-group">
                                <label>
                                    SSH Username
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="ssh_username"
                                    value={formData.ssh_username}
                                    onChange={handleChange}
                                    className={errors.ssh_username ? "error" : ""}
                                    placeholder="Enter SSH username"
                                    autoComplete="username"
                                />
                                {errors.ssh_username && <span className="error-message">{errors.ssh_username}</span>}
                            </div>

                            {needsSecret(dt) && (
                                <div className="form-group">
                                    <label>Enable Password</label>
                                    <input
                                        type="password"
                                        name="ssh_secret"
                                        value={formData.ssh_secret}
                                        onChange={handleChange}
                                        placeholder="Enable password (optional)"
                                        autoComplete="off"
                                    />
                                </div>
                            )}

                            <div className="form-group">
                                <label>SSH Port</label>
                                <input
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

                            {needsVdom(dt) && (
                                <div className="form-group">
                                    <label>VDOM</label>
                                    {vdomDiscovery?.vdoms?.length > 0 ? (
                                        <select
                                            name="vdom"
                                            value={formData.vdom}
                                            onChange={handleChange}
                                        >
                                            <option value="">All VDOMs</option>
                                            {vdomDiscovery.vdoms.map((v) => (
                                                <option key={v} value={v}>{v}</option>
                                            ))}
                                        </select>
                                    ) : (
                                        <input
                                            type="text"
                                            name="vdom"
                                            value={formData.vdom}
                                            onChange={handleChange}
                                            placeholder="VDOM name (optional)"
                                            autoComplete="off"
                                        />
                                    )}
                                    <button
                                        type="button"
                                        className="btn-cancel"
                                        onClick={handleDetectVdoms}
                                        disabled={vdomDiscovery?.isDiscovering}
                                        style={{ marginTop: "8px" }}
                                    >
                                        {vdomDiscovery?.isDiscovering ? "Detecting VDOMs…" : "Detect VDOMs"}
                                    </button>
                                    {vdomDiscovery?.error && (
                                        <span className="error-message">{vdomDiscovery.error}</span>
                                    )}
                                    {vdomDiscovery?.vdoms?.length > 0 && (
                                        <small className="form-hint">
                                            Detected {vdomDiscovery.vdoms.length} active VDOM(s):{" "}
                                            {vdomDiscovery.vdoms.join(", ")}. Choose one, or “All VDOMs”.
                                        </small>
                                    )}
                                    {vdomDiscovery?.vdoms?.length === 0 && (
                                        <small className="form-hint">
                                            No VDOMs detected — device is not VDOM-enabled.
                                        </small>
                                    )}
                                    {!vdomDiscovery?.vdoms && !vdomDiscovery?.isDiscovering && (
                                        <small className="form-hint">
                                            Enter credentials, then click “Detect VDOMs” to list active VDOMs.
                                        </small>
                                    )}
                                </div>
                            )}

                            {needsSudo(dt) && (
                                <div className="form-group">
                                    <label>Sudo Password</label>
                                    <input
                                        type="password"
                                        name="sudo_password"
                                        value={formData.sudo_password}
                                        onChange={handleChange}
                                        placeholder="Sudo password (optional)"
                                        autoComplete="off"
                                    />
                                </div>
                            )}

                            {isMongo(dt) && (
                                <>
                                    <div className="form-group">
                                        <label>MongoDB Username</label>
                                        <input
                                            type="text"
                                            name="mongo_username"
                                            value={formData.mongo_username}
                                            onChange={handleChange}
                                            placeholder="MongoDB username (optional)"
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

                            <div className="form-group form-group-full">
                                <label>
                                    SSH Password
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="ssh_password"
                                    value={formData.ssh_password}
                                    onChange={handleChange}
                                    className={errors.ssh_password ? "error" : ""}
                                    placeholder="Enter SSH password"
                                    autoComplete="current-password"
                                />
                                {errors.ssh_password && <span className="error-message">{errors.ssh_password}</span>}
                            </div>
                        </>
                    )}

                    {/* ══════════════════════════════════════════════════════
                        MSSQL credentials
                    ══════════════════════════════════════════════════════ */}
                    {isMssql(dt) && (
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
                                {errors.mssql_username && <span className="error-message">{errors.mssql_username}</span>}
                            </div>
                            <div className="form-group">
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
                                {errors.mssql_password && <span className="error-message">{errors.mssql_password}</span>}
                            </div>
                            <div className="form-group">
                                <label>SQL Server Port</label>
                                <input
                                    type="number"
                                    name="mssql_port"
                                    value={formData.mssql_port}
                                    onChange={handleChange}
                                    placeholder="1433"
                                    autoComplete="off"
                                />
                            </div>
                        </>
                    )}

                    {/* ══════════════════════════════════════════════════════
                        Windows credentials (WinRM)
                    ══════════════════════════════════════════════════════ */}
                    {isWindows(dt) && (
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
                                    placeholder="Administrator"
                                    autoComplete="username"
                                />
                                {errors.windows_username && <span className="error-message">{errors.windows_username}</span>}
                            </div>
                            <div className="form-group">
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
                                {errors.windows_password && <span className="error-message">{errors.windows_password}</span>}
                            </div>
                            <div className="form-group">
                                <label>WinRM Port</label>
                                <input
                                    type="number"
                                    name="winrm_port"
                                    value={formData.winrm_port}
                                    onChange={handleChange}
                                    placeholder={DEFAULT_WINRM_PORT}
                                    autoComplete="off"
                                />
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
                        </>
                    )}

                </div>

                {errors.submit && (
                    <div className="alert alert-error" style={{ marginTop: "16px" }}>
                        {errors.submit}
                    </div>
                )}

                <div className="form-actions">
                    <button type="button" className="btn-cancel" onClick={onCancel}>
                        Cancel
                    </button>
                    <button type="submit" className="btn-modal-primary" disabled={isLoading}>
                        {isLoading ? "Connecting..." : "Next"}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default HardeningConnectionForm;
