import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import { executeAuditWithDevice } from "../../store/hardeningSlice";

// ─── Device type list ─────────────────────────────────────────────────────────
const DEVICE_TYPES = [
    { value: "cisco",          label: "Cisco Router/Switch",         group: "Network" },
    { value: "fortinet",       label: "FortiGate Firewall",          group: "Network" },
    { value: "apache",         label: "Apache Web Server",           group: "Web Server" },
    { value: "mongodb",        label: "MongoDB",                     group: "Database" },
    { value: "mssql-2016",     label: "SQL Server 2016",             group: "Database" },
    { value: "mssql-2019",     label: "SQL Server 2019",             group: "Database" },
    { value: "mssql-2022",     label: "SQL Server 2022",             group: "Database" },
    { value: "windows-2016",   label: "Windows Server 2016",         group: "Windows" },
    { value: "windows-2022",   label: "Windows Server 2022",         group: "Windows" },
    { value: "windows-2025",   label: "Windows Server 2025",         group: "Windows" },
    { value: "linux-ubuntu-24",label: "Linux – Ubuntu 24.04 LTS",   group: "Linux" },
    { value: "linux-ubuntu-22",label: "Linux – Ubuntu 22.04 LTS",   group: "Linux" },
    { value: "linux-ubuntu-20",label: "Linux – Ubuntu 20.04 LTS",   group: "Linux" },
    { value: "linux-redhat-10",label: "Linux – Red Hat 10",         group: "Linux" },
    { value: "linux-redhat-9", label: "Linux – Red Hat 9",          group: "Linux" },
    { value: "linux-redhat-8", label: "Linux – Red Hat 8",          group: "Linux" },
    { value: "linux-rocky-10", label: "Linux – Rocky Linux 10",     group: "Linux" },
    { value: "linux-rocky-9",  label: "Linux – Rocky Linux 9",      group: "Linux" },
    { value: "linux-rocky-8",  label: "Linux – Rocky Linux 8",      group: "Linux" },
];

// ─── Asset filter mapping ─────────────────────────────────────────────────────
const DEVICE_TYPE_TO_ASSET_KEYWORDS = {
    "cisco":       ["cisco", "router", "switch"],
    "fortinet":    ["fortinet", "fortigate", "firewall"],
    "apache":      ["apache", "web server", "web"],
    "mongodb":     ["mongodb", "mongo", "database"],
    "mssql-2016":  ["mssql", "sql server", "microsoft sql", "sql"],
    "mssql-2019":  ["mssql", "sql server", "microsoft sql", "sql"],
    "mssql-2022":  ["mssql", "sql server", "microsoft sql", "sql"],
    "windows-2016":["windows", "windows server"],
    "windows-2022":["windows", "windows server"],
    "windows-2025":["windows", "windows server"],
};

const getFilteredAssets = (allAssets, deviceType) => {
    const keywords = DEVICE_TYPE_TO_ASSET_KEYWORDS[deviceType];
    if (!keywords) return allAssets; // linux و بقیه همه رو نشون میده
    const filtered = allAssets.filter(asset => {
        const typeName = (asset.asset_type_name || "").toLowerCase();
        const assetName = (asset.asset_name || "").toLowerCase();
        return keywords.some(kw => typeName.includes(kw) || assetName.includes(kw));
    });
    // اگه هیچ asset مطابقی پیدا نشد، همه رو نشون بده
    return filtered.length > 0 ? filtered : allAssets;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
const isLinux    = (dt) => dt?.startsWith("linux-");
const isCisco    = (dt) => dt === "cisco";
const isFortinet = (dt) => dt === "fortinet";
const isApache   = (dt) => dt === "apache";
const isMongo    = (dt) => dt === "mongodb";
const isMssql    = (dt) => dt?.startsWith("mssql-");
const isWindows  = (dt) => dt?.startsWith("windows-");

const needsSudo  = (dt) => isLinux(dt) || isApache(dt) || isMongo(dt);
const needsVdom  = (dt) => isFortinet(dt);
const needsSecret= (dt) => isCisco(dt);

// ─── Component ────────────────────────────────────────────────────────────────
export const HardeningConnectionForm = ({ onSubmit, onCancel }) => {
    const dispatch = useDispatch();
    const { assets }    = useSelector((state) => state.assets);
    const { isLoading } = useSelector((state) => state.hardening);

    const [formData, setFormData] = useState({
        device_type:      "cisco",
        asset_id:         "",
        job_name:         "",
        ssh_username:     "",
        ssh_password:     "",
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
        winrm_port:       "5986",
        transport:        "ntlm",
    });

    const [errors, setErrors] = useState({});

    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    const dt = formData.device_type;

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value,
            // وقتی device_type عوض شد، asset انتخاب شده رو reset کن
            ...(name === "device_type" ? { asset_id: "" } : {}),
        }));
        if (errors[name]) {
            setErrors((prev) => { const n = { ...prev }; delete n[name]; return n; });
        }
    };

    const validate = () => {
        const errs = {};

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
                winrm_port:       parseInt(formData.winrm_port) || 5986,
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
                ...(isCisco(dt)    && formData.ssh_secret    && { ssh_secret:    formData.ssh_secret }),
                ...(isFortinet(dt) && formData.vdom          && { vdom:          formData.vdom }),
                ...(needsSudo(dt)  && formData.sudo_password && { sudo_password: formData.sudo_password }),
                ...(isMongo(dt)    && formData.mongo_username && { mongo_username: formData.mongo_username }),
                ...(isMongo(dt)    && formData.mongo_password && { mongo_password: formData.mongo_password }),
                ...(isMongo(dt)    && { mongo_port: parseInt(formData.mongo_port) || 27017 }),
            };
        }

        const selectedAsset = assets.find((a) => a.id === assetId);
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
<<<<<<< HEAD
            const msg = err?.message || err?.toString() || "Failed to create hardening session";
=======
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
            
>>>>>>> 222b0db8fb59ae81f64bc3d84b533e46c853b57e
            setErrors({ submit: msg });
        }
    };

    const groups = [...new Set(DEVICE_TYPES.map((d) => d.group))];
    const filteredAssets = getFilteredAssets(assets || [], dt);

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Device Type ── */}
                    <div className="form-group form-group-full">
                        <label>
                            Device Type/Service Type
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>
                        <select
                            name="device_type"
                            value={formData.device_type}
                            onChange={handleChange}
                            className={errors.device_type ? "error" : ""}
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
                        {errors.device_type && <span className="error-message">{errors.device_type}</span>}
                    </div>

                    {/* ── Asset (فیلتر شده بر اساس device type) ── */}
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
                            <option value="">
                                Select ({filteredAssets.length} available)
                            </option>
                            {filteredAssets.map((asset) => (
                                <option key={asset.id} value={asset.id}>
                                    {asset.asset_name} ({asset.ip_address || "No IP"})
                                </option>
                            ))}
                        </select>
                        {errors.asset_id && <span className="error-message">{errors.asset_id}</span>}
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

                            {needsVdom(dt) && (
                                <div className="form-group">
                                    <label>VDOM</label>
                                    <input
                                        type="text"
                                        name="vdom"
                                        value={formData.vdom}
                                        onChange={handleChange}
                                        placeholder="VDOM name (optional)"
                                        autoComplete="off"
                                    />
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
                                    placeholder="5986"
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
<<<<<<< HEAD
};
=======
};

export default HardeningConnectionForm;
>>>>>>> 222b0db8fb59ae81f64bc3d84b533e46c853b57e
