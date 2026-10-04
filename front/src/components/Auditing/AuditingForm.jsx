/**
 * Audit wizard first step: pick the target (TargetPicker) and asset, enter the connection
 * credentials of that target (sent for this run only, never stored), and start the audit.
 */
import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import TargetPicker from "../shared/TargetPicker.jsx";
import { executeAudit } from "../../store/auditSlice";
import { discoverFortinetVdoms, clearVdomDiscovery } from "../../store/hardeningSlice";
import { FortinetBenchmarkModal } from "./FortinetBenchmarkModal";
import { DEFAULT_WINRM_PORT } from "../Hardening/winrmDefaults";
import {
    isCisco,
    isFortinet,
    isMongo,
    isMySQL,
    isESXi,
    isMssql,
    isSophos,
    usesWinRM,
    needsSudo,
} from "../Hardening/hardeningCredentials";
import { t } from "../../i18n";

// ─── Helpers ──────────────────────────────────────────────────────────────────
// Device-type predicates are imported from Hardening/hardeningCredentials.js —
// auditing and hardening connect to the same devices the same way, and keeping
// a second copy here is what let them drift apart before.

// ─── Component ────────────────────────────────────────────────────────────────
export const AuditingForm = ({ onSubmit, onCancel, onError }) => {
    const dispatch = useDispatch();
    const { isExecuting } = useSelector((state) => state.audit);
    const vdomDiscovery = useSelector((state) => state.hardening.vdomDiscovery);

    const [formData, setFormData] = useState({
        device_type:      "", // chosen by the target picker
        asset_id:         "",
        job_name:         "",
        ssh_username:     "",
        ssh_password:     "",
        ssh_port:         "22",
        enable_password:  "",
        vdom:             "",
        sudo_password:    "",
        mongo_username:   "",
        mongo_password:   "",
        mongo_port:       "27017",
        mysql_username:   "root",
        mysql_password:   "",
        mysql_port:       "3306",
        mssql_username:   "",
        mssql_password:   "",
        mssql_port:       "1433",
        sophos_username:  "",
        sophos_password:  "",
        sophos_port:      "4444",
        windows_username: "",
        windows_password: "",
        winrm_port:       DEFAULT_WINRM_PORT,
        transport:        "ntlm",
    });

    const [errors, setErrors] = useState({});
    const [showBenchmark, setShowBenchmark] = useState(false);

    // The picker owns the asset list; the form only keeps the chosen asset.
    const [selectedAsset, setSelectedAsset] = useState(null);

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
        const newErrors = {};
        if (!formData.asset_id) newErrors.asset_id = t("Please select an asset");
        if (!formData.ssh_username?.trim()) newErrors.ssh_username = t("Username is required");
        if (!formData.ssh_password?.trim()) newErrors.ssh_password = t("Password is required");
        if (Object.keys(newErrors).length) { setErrors(newErrors); return; }

        dispatch(discoverFortinetVdoms({
            asset_id:     parseInt(formData.asset_id),
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
            ssh_port:     parseInt(formData.ssh_port) || 22,
            mode:         "audit",
        }));
    };

    const validate = () => {
        const newErrors = {};

        if (!formData.device_type) newErrors.device_type = t("Choose what to audit");
        if (!formData.asset_id) newErrors.asset_id = t("Please select an asset");
        if (!formData.job_name || formData.job_name.trim().length < 2)
            newErrors.job_name = t("Job name must be at least 2 characters");

        if (usesWinRM(dt)) {
            if (!formData.windows_username?.trim()) newErrors.windows_username = t("Username is required");
            if (!formData.windows_password?.trim()) newErrors.windows_password = t("Password is required");
        } else if (isSophos(dt)) {
            if (!formData.sophos_username?.trim()) newErrors.sophos_username = t("Username is required");
            if (!formData.sophos_password?.trim()) newErrors.sophos_password = t("Password is required");
        } else if (isMssql(dt)) {
            if (!formData.mssql_username?.trim()) newErrors.mssql_username = t("Username is required");
            if (!formData.mssql_password?.trim()) newErrors.mssql_password = t("Password is required");
        } else {
            if (!formData.ssh_username?.trim()) newErrors.ssh_username = t("Username is required");
            if (!formData.ssh_password?.trim()) newErrors.ssh_password = t("Password is required");
            if (isMySQL(dt) && !formData.mysql_password?.trim()) newErrors.mysql_password = t("Password is required");
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!validate()) return;

        const assetId = parseInt(formData.asset_id);
        if (isNaN(assetId)) {
            setErrors({ asset_id: t("Please select a valid asset") });
            return;
        }

        const credentials = {
            asset_id:         assetId,
            job_name:         formData.job_name,
            ssh_username:     formData.ssh_username,
            ssh_password:     formData.ssh_password,
            ssh_port:         formData.ssh_port,
            ssh_secret:       formData.enable_password,
            vdom:             formData.vdom,
            sudo_password:    formData.sudo_password,
            mongo_username:   formData.mongo_username,
            mongo_password:   formData.mongo_password,
            mongo_port:       formData.mongo_port,
            mysql_username:   formData.mysql_username,
            mysql_password:   formData.mysql_password,
            mysql_port:       formData.mysql_port,
            mssql_username:   formData.mssql_username,
            mssql_password:   formData.mssql_password,
            mssql_port:       formData.mssql_port,
            sophos_username:  formData.sophos_username,
            sophos_password:  formData.sophos_password,
            sophos_port:      formData.sophos_port,
            windows_username: formData.windows_username,
            windows_password: formData.windows_password,
            winrm_port:       formData.winrm_port,
            transport:        formData.transport,
        };

        const tempSessionData = {
            session_id:  "pending",
            asset_name:  selectedAsset?.asset_name || "N/A",
            target_ip:   selectedAsset?.ip_address || "N/A",
            device_type: dt,
            status:      "pending",
        };

        onSubmit(tempSessionData, formData.job_name);

        try {
            const result = await dispatch(
                executeAudit({ deviceType: dt, formData: credentials })
            ).unwrap();
            onSubmit(result, formData.job_name);
        } catch (err) {
            // Extract error message from various possible formats
            let errorMessage = t("Failed to connect to server. Please check your connection and try again.");
            
            if (typeof err === "string") {
                errorMessage = err;
            } else if (err?.detail) {
                errorMessage = err.detail;
            } else if (err?.message) {
                errorMessage = err.message;
            } else if (err?.toString && err.toString() !== "[object Object]") {
                errorMessage = err.toString();
            }
            
            onError(errorMessage);
        }
    };

    return (
        <div className="auditing-form-container">
            {showBenchmark && (
                <FortinetBenchmarkModal onClose={() => setShowBenchmark(false)} />
            )}
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Target + asset (spans both columns) ── */}
                    <div className="form-group form-group-full" style={{ gridColumn: "1 / -1" }}>
                        <TargetPicker
                            mode="audit"
                            deviceType={formData.device_type}
                            assetId={formData.asset_id}
                            onChange={handleTargetChange}
                            errors={errors}
                        />
                    </div>

                    {/* ── Job Name ── */}
                    <div className="form-group">
                        <label>
                            {t("Job Name")}
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>
                        <input
                            type="text"
                            name="job_name"
                            value={formData.job_name}
                            onChange={handleChange}
                            className={errors.job_name ? "error" : ""}
                            placeholder={t("Enter job name")}
                            autoComplete="off"
                        />
                        {errors.job_name && <span className="error-message">{errors.job_name}</span>}
                    </div>

                    {/* ══════════════════════════════════════════════════════
                        SSH credentials
                    ══════════════════════════════════════════════════════ */}
                    {!usesWinRM(dt) && !isMssql(dt) && !isSophos(dt) && (
                        <>
                            <div className="form-group">
                                <label>
                                    {t("SSH Username")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="ssh_username"
                                    value={formData.ssh_username}
                                    onChange={handleChange}
                                    className={errors.ssh_username ? "error" : ""}
                                    placeholder={t("Enter SSH username")}
                                    autoComplete="username"
                                />
                                {errors.ssh_username && <span className="error-message">{errors.ssh_username}</span>}
                            </div>

                            {isCisco(dt) && (
                                <div className="form-group">
                                    <label>{t("Enable Password")}</label>
                                    <input
                                        type="password"
                                        name="enable_password"
                                        value={formData.enable_password}
                                        onChange={handleChange}
                                        placeholder={t("Enable password (optional)")}
                                        autoComplete="off"
                                    />
                                </div>
                            )}

                            {isFortinet(dt) && (
                                <div className="form-group form-group-full">
                                    <button
                                        type="button"
                                        className="btn-modal-secondary"
                                        onClick={() => setShowBenchmark(true)}
                                        style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
                                        title={t("View the full CIS FortiGate Benchmark checklist (53 controls)")}
                                    >
                                        <i className="fa-solid fa-list-check"></i> {" "}{t("Show CIS Benchmark")}
                                    </button>
                                </div>
                            )}

                            <div className="form-group">
                                <label>{t("SSH Port")}</label>
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

                            {isFortinet(dt) && (
                                <div className="form-group">
                                    <label>{t("VDOM")}</label>
                                    {vdomDiscovery?.vdoms?.length > 0 ? (
                                        <select
                                            name="vdom"
                                            value={formData.vdom}
                                            onChange={handleChange}
                                        >
                                            <option value="">{t("All VDOMs")}</option>
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
                                            placeholder={t("Leave blank to audit all VDOMs")}
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
                                        {vdomDiscovery?.isDiscovering ? t("Detecting VDOMs…") : t("Detect VDOMs")}
                                    </button>
                                    {vdomDiscovery?.error && (
                                        <span className="error-message">{vdomDiscovery.error}</span>
                                    )}
                                    {vdomDiscovery?.vdoms?.length > 0 && (
                                        <small className="form-hint">
                                            {t("Detected {{length}} active VDOM(s): {{join}}. Choose one, or “All VDOMs” to audit every VDOM.", { length: vdomDiscovery.vdoms.length, join: vdomDiscovery.vdoms.join(", ") })}
                                        </small>
                                    )}
                                    {vdomDiscovery?.vdoms?.length === 0 && (
                                        <small className="form-hint">
                                            {t("No VDOMs detected — device is not VDOM-enabled. The audit runs against the single (root) context.")}
                                        </small>
                                    )}
                                    {!vdomDiscovery?.vdoms && !vdomDiscovery?.isDiscovering && (
                                        <small className="form-hint">
                                            {t("Enter credentials, then click “Detect VDOMs” to list active VDOMs. Leave blank to audit every VDOM.")}
                                        </small>
                                    )}
                                </div>
                            )}

                            {isESXi(dt) && (
                                <div className="form-group form-group-full">
                                    <small className="form-hint">
                                        {t("ESXi has no sudo: sign in as root or an account with the Administrator role. SSH must be running on the host while the audit or hardening runs.")}
                                    </small>
                                </div>
                            )}

                            {needsSudo(dt) && (
                                <div className="form-group">
                                    <label>{t("Sudo Password")}</label>
                                    <input
                                        type="password"
                                        name="sudo_password"
                                        value={formData.sudo_password}
                                        onChange={handleChange}
                                        placeholder={t("Sudo password (optional)")}
                                        autoComplete="off"
                                    />
                                </div>
                            )}

                            {isMongo(dt) && (
                                <>
                                    <div className="form-group">
                                        <label>{t("MongoDB Username")}</label>
                                        <input
                                            type="text"
                                            name="mongo_username"
                                            value={formData.mongo_username}
                                            onChange={handleChange}
                                            placeholder={t("MongoDB username (optional)")}
                                            autoComplete="off"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>{t("MongoDB Password")}</label>
                                        <input
                                            type="password"
                                            name="mongo_password"
                                            value={formData.mongo_password}
                                            onChange={handleChange}
                                            placeholder={t("MongoDB password (optional)")}
                                            autoComplete="off"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>{t("MongoDB Port")}</label>
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

                            {isMySQL(dt) && (
                                <>
                                    <div className="form-group">
                                        <label>{t("MySQL Username")}</label>
                                        <input
                                            type="text"
                                            name="mysql_username"
                                            value={formData.mysql_username}
                                            onChange={handleChange}
                                            placeholder="root"
                                            autoComplete="off"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>
                                            {t("MySQL Password")}
                                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                                        </label>
                                        <input
                                            type="password"
                                            name="mysql_password"
                                            value={formData.mysql_password}
                                            onChange={handleChange}
                                            className={errors.mysql_password ? "error" : ""}
                                            placeholder={t("MySQL password")}
                                            autoComplete="off"
                                        />
                                        {errors.mysql_password && <span className="error-message">{errors.mysql_password}</span>}
                                    </div>
                                    <div className="form-group">
                                        <label>{t("MySQL Port")}</label>
                                        <input
                                            type="number"
                                            name="mysql_port"
                                            value={formData.mysql_port}
                                            onChange={handleChange}
                                            placeholder="3306"
                                            autoComplete="off"
                                        />
                                    </div>
                                </>
                            )}

                            <div className="form-group form-group-full">
                                <label>
                                    {t("SSH Password")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="ssh_password"
                                    value={formData.ssh_password}
                                    onChange={handleChange}
                                    className={errors.ssh_password ? "error" : ""}
                                    placeholder={t("Enter SSH password")}
                                    autoComplete="current-password"
                                />
                                {errors.ssh_password && <span className="error-message">{errors.ssh_password}</span>}
                            </div>
                        </>
                    )}

                    {/* ══════════════════════════════════════════════════════
                        Sophos Firewall XML API credentials
                    ══════════════════════════════════════════════════════ */}
                    {isSophos(dt) && (
                        <>
                            <div className="form-group">
                                <label>
                                    {t("API Username")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="sophos_username"
                                    value={formData.sophos_username}
                                    onChange={handleChange}
                                    className={errors.sophos_username ? "error" : ""}
                                    placeholder={t("Administrator with API access")}
                                    autoComplete="username"
                                />
                                {errors.sophos_username && <span className="error-message">{errors.sophos_username}</span>}
                            </div>
                            <div className="form-group">
                                <label>
                                    {t("API Password")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="sophos_password"
                                    value={formData.sophos_password}
                                    onChange={handleChange}
                                    className={errors.sophos_password ? "error" : ""}
                                    placeholder={t("API password")}
                                    autoComplete="current-password"
                                />
                                {errors.sophos_password && <span className="error-message">{errors.sophos_password}</span>}
                            </div>
                            <div className="form-group">
                                <label>{t("API Port")}</label>
                                <input
                                    type="number"
                                    name="sophos_port"
                                    value={formData.sophos_port}
                                    onChange={handleChange}
                                    placeholder="4444"
                                    autoComplete="off"
                                />
                            </div>
                            <div className="form-group form-group-full">
                                <small className="form-hint">
                                    {t("Enable the API on the firewall (Backup & firmware > API) and add this server's address to its allowed list. The firewall's certificate is pinned on first connection.")}
                                </small>
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
                                    {t("SQL Server Username")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="mssql_username"
                                    value={formData.mssql_username}
                                    onChange={handleChange}
                                    className={errors.mssql_username ? "error" : ""}
                                    placeholder={t("sa or sysadmin account")}
                                    autoComplete="username"
                                />
                                {errors.mssql_username && <span className="error-message">{errors.mssql_username}</span>}
                            </div>
                            <div className="form-group">
                                <label>
                                    {t("SQL Server Password")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="mssql_password"
                                    value={formData.mssql_password}
                                    onChange={handleChange}
                                    className={errors.mssql_password ? "error" : ""}
                                    placeholder={t("SQL Server password")}
                                    autoComplete="current-password"
                                />
                                {errors.mssql_password && <span className="error-message">{errors.mssql_password}</span>}
                            </div>
                            <div className="form-group">
                                <label>{t("SQL Server Port")}</label>
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
                    {usesWinRM(dt) && (
                        <>
                            <div className="form-group">
                                <label>
                                    {t("Windows Username")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="text"
                                    name="windows_username"
                                    value={formData.windows_username}
                                    onChange={handleChange}
                                    className={errors.windows_username ? "error" : ""}
                                    placeholder={t("Administrator")}
                                    autoComplete="username"
                                />
                                {errors.windows_username && <span className="error-message">{errors.windows_username}</span>}
                            </div>
                            <div className="form-group">
                                <label>
                                    {t("Windows Password")}
                                    <span className="required" style={{ color: "#ef4444" }}>*</span>
                                </label>
                                <input
                                    type="password"
                                    name="windows_password"
                                    value={formData.windows_password}
                                    onChange={handleChange}
                                    className={errors.windows_password ? "error" : ""}
                                    placeholder={t("Windows admin password")}
                                    autoComplete="current-password"
                                />
                                {errors.windows_password && <span className="error-message">{errors.windows_password}</span>}
                            </div>
                            <div className="form-group">
                                <label>{t("WinRM Port")}</label>
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
                                <label>{t("Transport")}</label>
                                <select name="transport" value={formData.transport} onChange={handleChange}>
                                    <option value="ntlm">{t("NTLM")}</option>
                                    <option value="kerberos">{t("Kerberos")}</option>
                                    <option value="credssp">{t("CredSSP")}</option>
                                    <option value="basic">{t("Basic")}</option>
                                </select>
                            </div>
                        </>
                    )}

                </div>

                {/* Actions */}
                <div className="form-actions">
                    <button
                        type="button"
                        className="btn-cancel"
                        onClick={onCancel}
                        disabled={isExecuting}
                    >
                        {t("Cancel")}
                    </button>
                    <button
                        type="submit"
                        className="btn-submit"
                        disabled={isExecuting}
                    >
                        {t("Next")}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default AuditingForm;
