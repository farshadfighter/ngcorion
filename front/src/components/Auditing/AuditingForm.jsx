import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import { executeAudit } from "../../store/auditSlice";
import { discoverFortinetVdoms } from "../../store/hardeningSlice";

// ─── Device type list ─────────────────────────────────────────────────────────
const DEVICE_TYPES = [
    // ── Network ────────────────────────────────────────────────────────────────
    { value: "cisco",           label: "Cisco Router/Switch",       group: "Network"    },
    { value: "fortinet",        label: "FortiGate Firewall",         group: "Network"    },
    // ── Web Server ─────────────────────────────────────────────────────────────
    { value: "apache",          label: "Apache Web Server",          group: "Web Server" },
    // ── Database ───────────────────────────────────────────────────────────────
    { value: "mongodb",         label: "MongoDB",                    group: "Database"   },
    { value: "mssql-2016",      label: "SQL Server 2016",            group: "Database"   },
    { value: "mssql-2019",      label: "SQL Server 2019",            group: "Database"   },
    { value: "mssql-2022",      label: "SQL Server 2022",            group: "Database"   },
    // ── Windows ────────────────────────────────────────────────────────────────
    { value: "windows-2016",    label: "Windows Server 2016",        group: "Windows"    },
    { value: "windows-2022",    label: "Windows Server 2022",        group: "Windows"    },
    { value: "windows-2025",    label: "Windows Server 2025",        group: "Windows"    },
    // ── Ubuntu ─────────────────────────────────────────────────────────────────
    { value: "linux-ubuntu-24", label: "Linux – Ubuntu 24.04 LTS",  group: "Linux"      },
    { value: "linux-ubuntu-22", label: "Linux – Ubuntu 22.04 LTS",  group: "Linux"      },
    { value: "linux-ubuntu-20", label: "Linux – Ubuntu 20.04 LTS",  group: "Linux"      },
    // ── Red Hat ────────────────────────────────────────────────────────────────
    { value: "linux-redhat-10", label: "Linux – Red Hat 10",        group: "Linux"      },
    { value: "linux-redhat-9",  label: "Linux – Red Hat 9",         group: "Linux"      },
    { value: "linux-redhat-8",  label: "Linux – Red Hat 8",         group: "Linux"      },
    // ── Rocky ──────────────────────────────────────────────────────────────────
    { value: "linux-rocky-10",  label: "Linux – Rocky Linux 10",    group: "Linux"      },
    { value: "linux-rocky-9",   label: "Linux – Rocky Linux 9",     group: "Linux"      },
    { value: "linux-rocky-8",   label: "Linux – Rocky Linux 8",     group: "Linux"      },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────
const isLinux    = (dt) => dt?.startsWith("linux-");
const isCisco    = (dt) => dt === "cisco";
const isFortinet = (dt) => dt === "fortinet";
const isApache   = (dt) => dt === "apache";
const isMongo    = (dt) => dt === "mongodb";
const isMssql    = (dt) => dt?.startsWith("mssql-");
const isWindows  = (dt) => dt?.startsWith("windows-");
const needsSudo  = (dt) => isLinux(dt) || isApache(dt) || isMongo(dt);

// ─── Component ────────────────────────────────────────────────────────────────
export const AuditingForm = ({ onSubmit, onCancel, onError }) => {
    const dispatch = useDispatch();
    const { assets } = useSelector((state) => state.assets);
    const { isExecuting } = useSelector((state) => state.audit);
    const { vdomDiscovery } = useSelector((state) => state.hardening);

    const [formData, setFormData] = useState({
        device_type:      "cisco",
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
        mssql_username:   "",
        mssql_password:   "",
        mssql_port:       "1433",
        windows_username: "",
        windows_password: "",
        winrm_port:       "5986",
        transport:        "ntlm",
    });

    const [errors, setErrors] = useState({});

    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    const dt = formData.device_type;
    const groups = [...new Set(DEVICE_TYPES.map((d) => d.group))];

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (errors[name]) {
            setErrors((prev) => { const n = { ...prev }; delete n[name]; return n; });
        }
    };

    const handleDetectVdoms = () => {
        if (!formData.asset_id || !formData.ssh_username || !formData.ssh_password) return;
        dispatch(discoverFortinetVdoms({
            asset_id:     parseInt(formData.asset_id),
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
            ssh_port:     parseInt(formData.ssh_port) || 22,
        }));
    };

    const validate = () => {
        const newErrors = {};

        if (!formData.asset_id) newErrors.asset_id = "Please select an asset";
        if (!formData.job_name || formData.job_name.trim().length < 2)
            newErrors.job_name = "Job name must be at least 2 characters";

        if (isWindows(dt)) {
            if (!formData.windows_username?.trim()) newErrors.windows_username = "Username is required";
            if (!formData.windows_password?.trim()) newErrors.windows_password = "Password is required";
        } else if (isMssql(dt)) {
            if (!formData.mssql_username?.trim()) newErrors.mssql_username = "Username is required";
            if (!formData.mssql_password?.trim()) newErrors.mssql_password = "Password is required";
        } else {
            if (!formData.ssh_username?.trim()) newErrors.ssh_username = "Username is required";
            if (!formData.ssh_password?.trim()) newErrors.ssh_password = "Password is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!validate()) return;

        const assetId = parseInt(formData.asset_id);
        if (isNaN(assetId)) {
            setErrors({ asset_id: "Please select a valid asset" });
            return;
        }

        const credentials = {
            asset_id:         assetId,
            job_name:         formData.job_name,
            ssh_username:     formData.ssh_username,
            ssh_password:     formData.ssh_password,
            ssh_port:         parseInt(formData.ssh_port) || 22,
            ssh_secret:       formData.enable_password,
            vdom:             formData.vdom,
            sudo_password:    formData.sudo_password,
            mongo_username:   formData.mongo_username,
            mongo_password:   formData.mongo_password,
            mongo_port:       formData.mongo_port,
            mssql_username:   formData.mssql_username,
            mssql_password:   formData.mssql_password,
            mssql_port:       formData.mssql_port,
            windows_username: formData.windows_username,
            windows_password: formData.windows_password,
            winrm_port:       formData.winrm_port,
            transport:        formData.transport,
        };

        const selectedAsset = assets.find((a) => a.id === assetId);
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
            const errorMessage =
                err?.detail ||
                err?.message ||
                err?.toString() ||
                "Failed to connect to server. Please check your connection and try again.";
            onError(errorMessage);
        }
    };

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Device Type ──────────────────────────────────────── */}
                    <div className="form-group form-group-full">
                        <label>
                            Device Type / Service Type
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>
                        <select
                            name="device_type"
                            value={dt}
                            onChange={handleChange}
                            className={`device-type-selector ${errors.device_type ? "error" : ""}`}
                        >
                            {groups.map((group) => (
                                <optgroup key={group} label={group}>
                                    {DEVICE_TYPES.filter((d) => d.group === group).map((d) => (
                                        <option key={d.value} value={d.value}>
                                            {d.label}
                                        </option>
                                    ))}
                                </optgroup>
                            ))}
                        </select>
                    </div>

                    {/* ── Asset ────────────────────────────────────────────── */}
                    <div className="form-group">
                        <label>
                            Select Asset
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>
                        <select
                            name="asset_id"
                            value={formData.asset_id}
                            onChange={handleChange}
                            className={errors.asset_id ? "error" : ""}
                        >
                            <option value="">Select</option>
                            {assets?.map((asset) => (
                                <option key={asset.id} value={asset.id}>
                                    {asset.asset_name} ({asset.ip_address || "No IP"})
                                </option>
                            ))}
                        </select>
                        {errors.asset_id && <span className="error-message">{errors.asset_id}</span>}
                    </div>

                    {/* ── Job Name ─────────────────────────────────────────── */}
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
                        />
                        {errors.job_name && <span className="error-message">{errors.job_name}</span>}
                    </div>

                    {/* ══════════════════════════════════════════════════════
                        SSH-based: Cisco, Fortinet, Linux, Apache, MongoDB
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

                            {isCisco(dt) && (
                                <div className="form-group">
                                    <label>Enable Password</label>
                                    <input
                                        type="password"
                                        name="enable_password"
                                        value={formData.enable_password}
                                        onChange={handleChange}
                                        placeholder="Enable password (optional)"
                                        autoComplete="off"
                                    />
                                    <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                        Required for privileged commands
                                    </span>
                                </div>
                            )}

                            {isFortinet(dt) && (
                                <div className="form-group">
                                    <label>VDOM</label>
                                    <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "6px" }}>
                                        <button
                                            type="button"
                                            onClick={handleDetectVdoms}
                                            disabled={vdomDiscovery?.isDiscovering || !formData.ssh_username || !formData.ssh_password || !formData.asset_id}
                                            style={{
                                                padding: "6px 14px", fontSize: "13px", fontWeight: "600",
                                                background: "#2563eb", color: "white", border: "none",
                                                borderRadius: "6px", cursor: "pointer",
                                                opacity: (vdomDiscovery?.isDiscovering || !formData.ssh_username || !formData.ssh_password || !formData.asset_id) ? 0.5 : 1,
                                            }}
                                        >
                                            {vdomDiscovery?.isDiscovering ? "Detecting…" : "Detect VDOMs"}
                                        </button>
                                        {vdomDiscovery?.vdoms !== null && !vdomDiscovery?.isDiscovering && (
                                            <span style={{
                                                padding: "3px 10px", borderRadius: "12px", fontSize: "12px", fontWeight: "600",
                                                background: vdomDiscovery.vdoms.length > 0 ? "#d1fae5" : "#f3f4f6",
                                                color: vdomDiscovery.vdoms.length > 0 ? "#065f46" : "#6b7280",
                                                border: `1px solid ${vdomDiscovery.vdoms.length > 0 ? "#6ee7b7" : "#d1d5db"}`,
                                            }}>
                                                {vdomDiscovery.vdoms.length > 0
                                                    ? `✓ VDOM Enabled (${vdomDiscovery.vdoms.length})`
                                                    : "VDOM Disabled"}
                                            </span>
                                        )}
                                    </div>
                                    {vdomDiscovery?.error && (
                                        <span style={{ fontSize: "12px", color: "#dc2626", display: "block", marginBottom: "4px" }}>
                                            {vdomDiscovery.error}
                                        </span>
                                    )}
                                    {vdomDiscovery?.vdoms?.length > 0 ? (
                                        <select
                                            name="vdom"
                                            value={formData.vdom}
                                            onChange={handleChange}
                                            style={{ width: "100%", padding: "8px 10px", borderRadius: "6px", border: "1px solid #d1d5db", fontSize: "14px" }}
                                        >
                                            <option value="">Select VDOM (default: root)</option>
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
                                            placeholder="Virtual Domain (optional, default: root)"
                                            autoComplete="off"
                                        />
                                    )}
                                    <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                        Click "Detect VDOMs" to discover available virtual domains
                                    </span>
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
                                    <span style={{ fontSize: "12px", color: "#6b7280", display: "block", marginTop: "4px" }}>
                                        Required for root access (defaults to SSH password)
                                    </span>
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
                                {errors.mssql_password && <span className="error-message">{errors.mssql_password}</span>}
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
                                    placeholder="Administrator or DOMAIN\user"
                                    autoComplete="username"
                                />
                                {errors.windows_username && <span className="error-message">{errors.windows_username}</span>}
                            </div>
                            <div className="form-group">
                                <label>WinRM Port</label>
                                <input
                                    type="number"
                                    name="winrm_port"
                                    value={formData.winrm_port}
                                    onChange={handleChange}
                                    placeholder="5986"
                                    autoComplete="off"
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
                                {errors.windows_password && <span className="error-message">{errors.windows_password}</span>}
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
                        Cancel
                    </button>
                    <button
                        type="submit"
                        className="btn-submit"
                        disabled={isExecuting}
                    >
                        Next
                    </button>
                </div>
            </form>
        </div>
    );
};

export default AuditingForm;