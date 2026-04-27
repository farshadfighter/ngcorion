import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import { executeAudit } from "../../store/auditSlice";

export const AuditingForm = ({ onSubmit, onCancel, onError }) => {
    const dispatch = useDispatch();
    const { assets } = useSelector((state) => state.assets);
    const { isExecuting } = useSelector((state) => state.audit);

    const [formData, setFormData] = useState({
        device_type:      "cisco",
        asset_id:         "",
        job_name:         "",
        // SSH-based
        ssh_username:     "",
        ssh_password:     "",
        enable_password:  "",   // Cisco
        vdom:             "",   // Fortinet
        sudo_password:    "",   // Linux / Apache / MongoDB
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

    const deviceTypes = [
        // Network
        { value: "cisco",           label: "Cisco Router/Switch" },
        { value: "fortinet",        label: "FortiGate Firewall" },
        // Web Server
        { value: "apache",          label: "Apache Web Server" },
        // Database
        { value: "mongodb",         label: "MongoDB" },
        { value: "mssql-2016",      label: "SQL Server 2016" },
        { value: "mssql-2019",      label: "SQL Server 2019" },
        { value: "mssql-2022",      label: "SQL Server 2022" },
        // Windows
        { value: "windows-2016",    label: "Windows Server 2016" },
        { value: "windows-2022",    label: "Windows Server 2022" },
        { value: "windows-2025",    label: "Windows Server 2025" },
        // Linux - Ubuntu
        { value: "linux-ubuntu-24", label: "Linux - Ubuntu 24.04 LTS" },
        { value: "linux-ubuntu-22", label: "Linux - Ubuntu 22.04 LTS" },
        { value: "linux-ubuntu-20", label: "Linux - Ubuntu 20.04 LTS" },
        // Linux - Red Hat
        { value: "linux-redhat-10", label: "Linux - Red Hat 10" },
        { value: "linux-redhat-9",  label: "Linux - Red Hat 9" },
        { value: "linux-redhat-8",  label: "Linux - Red Hat 8" },
        // Linux - Rocky
        { value: "linux-rocky-10",  label: "Linux - Rocky Linux 10" },
        { value: "linux-rocky-9",   label: "Linux - Rocky Linux 9" },
        { value: "linux-rocky-8",   label: "Linux - Rocky Linux 8" },
    ];

    const [errors, setErrors] = useState({});

    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    const dt = formData.device_type;
    const isWindows = dt.startsWith("windows-");
    const isMssql   = dt.startsWith("mssql-");
    const isMongo   = dt === "mongodb";
    const isLinux   = dt.startsWith("linux-");
    const isApache  = dt === "apache";
    const isCisco   = dt === "cisco";
    const isFortinet= dt === "fortinet";
    const needsSudo = isLinux || isApache || isMongo;

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        if (errors[name]) {
            setErrors((prev) => {
                const newErrors = { ...prev };
                delete newErrors[name];
                return newErrors;
            });
        }
    };

    const validate = () => {
        const newErrors = {};

        if (!formData.asset_id) {
            newErrors.asset_id = "Please select an asset";
        }
        if (!formData.job_name || formData.job_name.trim().length < 2) {
            newErrors.job_name = "Job name must be at least 2 characters";
        }

        if (isWindows) {
            if (!formData.windows_username?.trim()) newErrors.windows_username = "Username is required";
            if (!formData.windows_password?.trim()) newErrors.windows_password = "Password is required";
        } else if (isMssql) {
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
            asset_id: assetId,
            job_name: formData.job_name,
            // SSH
            ssh_username:     formData.ssh_username,
            ssh_password:     formData.ssh_password,
            ssh_secret:       formData.enable_password,
            vdom:             formData.vdom,
            sudo_password:    formData.sudo_password,
            // MongoDB
            mongo_username:   formData.mongo_username,
            mongo_password:   formData.mongo_password,
            mongo_port:       formData.mongo_port,
            // MSSQL
            mssql_username:   formData.mssql_username,
            mssql_password:   formData.mssql_password,
            mssql_port:       formData.mssql_port,
            // Windows
            windows_username: formData.windows_username,
            windows_password: formData.windows_password,
            winrm_port:       formData.winrm_port,
            transport:        formData.transport,
        };

        const selectedAsset = assets.find(a => a.id === assetId);
        const tempSessionData = {
            session_id:  "pending",
            asset_name:  selectedAsset?.asset_name || "N/A",
            target_ip:   selectedAsset?.ip_address || "N/A",
            device_type: formData.device_type,
            status:      "pending"
        };

        // ✅ اول برو به step 2 (Process)
        onSubmit(tempSessionData, formData.job_name);

        // ✅ بعد API رو صدا بزن
        try {
            const result = await dispatch(
                executeAudit({
                    deviceType: formData.device_type,
                    formData: credentials,
                })
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
                <input type="hidden" name="device_type" value={formData.device_type} />

                <div className="form-grid-two-column">

                    {/* Device Type */}
                    <div className="form-group form-group-full">
                        <label>Device Type <span className="required">*</span></label>
                        <select
                            name="device_type"
                            value={formData.device_type}
                            onChange={handleChange}
                            className={`device-type-selector ${errors.device_type ? "error" : ""}`}
                        >
                            {deviceTypes.map((type) => (
                                <option key={type.value} value={type.value}>
                                    {type.label}
                                </option>
                            ))}
                        </select>
                    </div>

                    {/* Select Asset */}
                    <div className="form-group">
                        <label>Select Asset <span className="required">*</span></label>
                        <select
                            name="asset_id"
                            value={formData.asset_id}
                            onChange={handleChange}
                            className={errors.asset_id ? "error" : ""}
                        >
                            <option value="">select</option>
                            {assets && assets.map((asset) => (
                                <option key={asset.id} value={asset.id}>
                                    {asset.asset_name} ({asset.ip_address || "No IP"})
                                </option>
                            ))}
                        </select>
                        {errors.asset_id && <span className="error-message">{errors.asset_id}</span>}
                    </div>

                    {/* Job Name */}
                    <div className="form-group">
                        <label>Job Name <span className="required">*</span></label>
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

                    {/* ══════════════════════════════════════════
                        SSH-based: Cisco, Fortinet, Linux, Apache, MongoDB
                    ══════════════════════════════════════════ */}
                    {!isWindows && !isMssql && (
                        <>
                            {/* Username */}
                            <div className="form-group">
                                <label>UserName <span className="required">*</span></label>
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

                            {/* CISCO ONLY: Enable Password */}
                            {isCisco && (
                                <div className="form-group">
                                    <label>Enable Password</label>
                                    <input
                                        type="password"
                                        name="enable_password"
                                        value={formData.enable_password}
                                        onChange={handleChange}
                                        placeholder="Enter enable password (optional)"
                                        autoComplete="off"
                                    />
                                    <span style={{ fontSize: '12px', color: '#6b7280', display: 'block', marginTop: '4px' }}>
                                        Required for privileged commands
                                    </span>
                                </div>
                            )}

                            {/* FORTINET ONLY: VDOM */}
                            {isFortinet && (
                                <div className="form-group">
                                    <label>VDOM</label>
                                    <input
                                        type="text"
                                        name="vdom"
                                        value={formData.vdom}
                                        onChange={handleChange}
                                        placeholder="Virtual Domain (optional, default: root)"
                                        autoComplete="off"
                                    />
                                    <span style={{ fontSize: '12px', color: '#6b7280', display: 'block', marginTop: '4px' }}>
                                        Leave empty for default VDOM
                                    </span>
                                </div>
                            )}

                            {/* Linux / Apache / MongoDB: Sudo Password */}
                            {needsSudo && (
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
                                    <span style={{ fontSize: '12px', color: '#6b7280', display: 'block', marginTop: '4px' }}>
                                        Required for root access (defaults to SSH password)
                                    </span>
                                </div>
                            )}

                            {/* MongoDB: extra DB credentials */}
                            {isMongo && (
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
                                <label>Password <span className="required">*</span></label>
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

                    {/* ══════════════════════════════════════════
                        MSSQL credentials
                    ══════════════════════════════════════════ */}
                    {isMssql && (
                        <>
                            <div className="form-group">
                                <label>SQL Server Username <span className="required">*</span></label>
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
                                <label>SQL Server Password <span className="required">*</span></label>
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

                    {/* ══════════════════════════════════════════
                        Windows credentials (WinRM)
                    ══════════════════════════════════════════ */}
                    {isWindows && (
                        <>
                            <div className="form-group">
                                <label>Windows Username <span className="required">*</span></label>
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
                                <span style={{ fontSize: '12px', color: '#6b7280', display: 'block', marginTop: '4px' }}>
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
                                <label>Windows Password <span className="required">*</span></label>
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
                        cancel
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