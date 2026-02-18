import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import { executeAudit } from "../../store/auditSlice";

export const AuditingForm = ({ onSubmit, onCancel, onError }) => {
    const dispatch = useDispatch();
    const { assets } = useSelector((state) => state.assets);
    const { isExecuting } = useSelector((state) => state.audit);

    const [formData, setFormData] = useState({
        device_type: "cisco",
        asset_id: "",
        job_name: "",
        ssh_username: "",
        ssh_password: "",
        enable_password: "",
        vdom: "",
        sudo_password: "",
    });

    const deviceTypes = [
        { value: "cisco", label: "Cisco Router/Switch" },
        { value: "fortinet", label: "FortiGate Firewall" },
        { value: "linux-ubuntu-22.04", label: "Linux - Ubuntu 22.04 LTS" },
        { value: "linux-ubuntu-24.04", label: "Linux - Ubuntu 24.04 LTS" },
        { value: "linux-rocky-8", label: "Linux - Rocky Linux 8" },
        { value: "apache", label: "Apache Web Server" },
    ];

    const [errors, setErrors] = useState({});

    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

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
        if (!formData.ssh_username || formData.ssh_username.trim().length < 1) {
            newErrors.ssh_username = "Username is required";
        }
        if (!formData.ssh_password || formData.ssh_password.trim().length < 1) {
            newErrors.ssh_password = "Password is required";
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
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
            job_name: formData.job_name, // ✅ اضافه شد
        };

        if (formData.device_type === "cisco" && formData.enable_password) {
            credentials.ssh_secret = formData.enable_password;
        }
        if (formData.device_type === "fortinet" && formData.vdom) {
            credentials.vdom = formData.vdom;
        }
        if ((formData.device_type.startsWith("linux-") || formData.device_type === "apache") && formData.sudo_password) {
            credentials.sudo_password = formData.sudo_password;
        }

        // ساخت tempSessionData برای نمایش فوری Process
        const selectedAsset = assets.find(a => a.id === assetId);
        const tempSessionData = {
            session_id: "pending",
            asset_name: selectedAsset?.asset_name || "N/A",
            target_ip: selectedAsset?.ip_address || "N/A",
            device_type: formData.device_type,
            status: "pending"
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

            // ✅ موفق - session_id واقعی رو پاس بده
            onSubmit(result, formData.job_name);

        } catch (err) {
            // ✅ هر خطایی (500, network, timeout) → برو به صفحه Failed
            const errorMessage =
                err?.detail ||
                err?.message ||
                err?.toString() ||
                "Failed to connect to server. Please check your connection and try again.";

            // ✅ به جای نشون دادن خطا در فرم، برو به صفحه Failed
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
                    {formData.device_type === "cisco" && (
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
                    {formData.device_type === "fortinet" && (
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

                    {/* LINUX: Sudo Password */}
                    {formData.device_type.startsWith("linux-") && (
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

                    {/* APACHE: Sudo Password */}
                    {formData.device_type === "apache" && (
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

                    {/* Password */}
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
