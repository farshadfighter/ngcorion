import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import { executeAuditWithDevice } from "../../store/hardeningSlice";

export const HardeningConnectionForm = ({ onSubmit, onCancel }) => {
    const dispatch = useDispatch();
    const { assets } = useSelector((state) => state.assets);
    const { isLoading } = useSelector((state) => state.hardening);

    const [formData, setFormData] = useState({
        device_type: "cisco",
        asset_id: "",
        ssh_username: "",
        ssh_password: "",
        ssh_secret: "",      // Cisco only
        vdom: "",            // Fortinet only
        sudo_password: "",   // Linux/Apache only
    });

    const [errors, setErrors] = useState({});

    // Device Types - 6 total
    const deviceTypes = [
        { value: "cisco", label: "Cisco Router/Switch" },
        { value: "fortinet", label: "FortiGate Firewall" },
        { value: "linux-ubuntu-22.04", label: "Linux - Ubuntu 22.04 LTS" },
        { value: "linux-ubuntu-24.04", label: "Linux - Ubuntu 24.04 LTS" },
        { value: "linux-rocky-8", label: "Linux - Rocky Linux 8" },
        { value: "apache", label: "Apache Web Server" },
    ];

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

        if (!validate()) {
            return;
        }

        const assetId = parseInt(formData.asset_id);
        if (isNaN(assetId)) {
            setErrors({ asset_id: "Please select a valid asset" });
            return;
        }

        // Prepare credentials
        const credentials = {
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
        };

        // Add device-specific credentials
        if (formData.device_type === "cisco" && formData.ssh_secret) {
            credentials.ssh_secret = formData.ssh_secret;
        }
        if (formData.device_type === "fortinet" && formData.vdom) {
            credentials.vdom = formData.vdom;
        }
        if ((formData.device_type.startsWith("linux-") || formData.device_type === "apache") && formData.sudo_password) {
            credentials.sudo_password = formData.sudo_password;
        }

        // ✅ Immediately go to step 2 with temp data
        const selectedAsset = assets.find(a => a.id === assetId);
        const tempSessionData = {
            session_id: "pending",
            asset_name: selectedAsset?.asset_name || "N/A",
            target_ip: selectedAsset?.ip_address || "N/A",
            device_type: formData.device_type,
            status: "pending"
        };

        onSubmit(tempSessionData);

        // ✅ THEN dispatch API call in background
        try {
            const result = await dispatch(
                executeAuditWithDevice({
                    deviceType: formData.device_type,
                    assetId,
                    credentials
                })
            ).unwrap();

            // Update with real session data
            onSubmit(result);
        } catch (err) {
            const errorMessage = err?.message || err?.toString() || "Failed to create hardening session";
            setErrors({ submit: errorMessage });
        }
    };

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">
                    {/* Device Type Selector - First Field */}
                    <div className="form-group form-group-full">
                        <label>
                            Device Type
                            <span className="required" style={{color: '#ef4444'}}>*</span>
                        </label>
                        <select
                            name="device_type"
                            value={formData.device_type}
                            onChange={handleChange}
                            className={errors.device_type ? "error" : ""}
                        >
                            {deviceTypes.map((type) => (
                                <option key={type.value} value={type.value}>
                                    {type.label}
                                </option>
                            ))}
                        </select>
                        {errors.device_type && (
                            <span className="error-message">{errors.device_type}</span>
                        )}
                    </div>

                    {/* Select Asset */}
                    <div className="form-group">
                        <label>Select Asset <span className="required" style={{color: '#ef4444'}}>*</span></label>
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

                    {/* SSH Username */}
                    <div className="form-group">
                        <label>UserName <span className="required" style={{color: '#ef4444'}}>*</span></label>
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
                                name="ssh_secret"
                                value={formData.ssh_secret}
                                onChange={handleChange}
                                placeholder="Enter enable password (optional)"
                                autoComplete="off"
                            />
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
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
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
                                Leave empty for default VDOM
                            </span>
                        </div>
                    )}

                    {/* LINUX (ALL 3 VARIANTS): Sudo Password */}
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
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
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
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
                                Required for root access (defaults to SSH password)
                            </span>
                        </div>
                    )}

                    {/* SSH Password - Always Last */}
                    <div className="form-group form-group-full">
                        <label>Password <span className="required" style={{color: '#ef4444'}}>*</span></label>
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

                {/* Submit Error */}
                {errors.submit && (
                    <div className="alert alert-error">{errors.submit}</div>
                )}

                {/* Actions */}
                <div className="form-actions">
                    <button
                        type="button"
                        className="btn-cancel"
                        onClick={onCancel}
                        disabled={isLoading}
                        style={{
                            padding: '12px 28px',
                            background: 'white',
                            border: '1px solid #d1d5db',
                            borderRadius: '8px',
                            fontSize: '14px',
                            fontWeight: '600',
                            color: '#374151',
                            cursor: 'pointer'
                        }}
                    >
                        cancel
                    </button>
                    <button
                        type="submit"
                        className="btn-see-result"
                        disabled={isLoading}
                    >
                        Next
                    </button>
                </div>
            </form>
        </div>
    );
};

export default HardeningConnectionForm;