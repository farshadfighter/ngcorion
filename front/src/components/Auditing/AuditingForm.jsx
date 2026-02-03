import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets } from "../../store/assetSlice";
import { executeAudit } from "../../store/auditSlice";

export const AuditingForm = ({ onSubmit, onCancel }) => {
    const dispatch = useDispatch();
    const { assets } = useSelector((state) => state.assets);
    const { isExecuting } = useSelector((state) => state.audit);

    const [formData, setFormData] = useState({
        device_type: "cisco",
        asset_id: "",
        job_name: "",
        ssh_username: "",
        ssh_password: "",
        enable_password: "",  // Cisco only
        vdom: "",  // FortiGate only
    });

    // Device type options with implementation status
    const deviceTypes = [
        { value: "cisco", label: "Cisco Router/Switch", implemented: true },
        { value: "fortinet", label: "FortiGate Firewall", implemented: true },
        { value: "linux", label: "Linux Server", implemented: false },
        { value: "windows", label: "Windows Server", implemented: false },
        { value: "apache", label: "Apache Web Server", implemented: false },
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

        // Only validate credentials for implemented device types
        if (formData.device_type === "cisco" || formData.device_type === "fortinet") {
            if (!formData.ssh_username || formData.ssh_username.trim().length < 1) {
                newErrors.ssh_username = "Username is required";
            }
            if (!formData.ssh_password || formData.ssh_password.trim().length < 1) {
                newErrors.ssh_password = "Password is required";
            }
        }

        // Prevent submission for unimplemented devices
        if (["linux", "windows", "apache"].includes(formData.device_type)) {
            newErrors.device_type = "This device type is not yet implemented";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validate()) {
            return;
        }

        try {
            // Prepare credentials based on device type
            const credentials = {
                asset_id: parseInt(formData.asset_id),
                ssh_username: formData.ssh_username,
                ssh_password: formData.ssh_password,
            };

            // Add device-specific fields
            if (formData.device_type === "cisco" && formData.enable_password) {
                credentials.ssh_secret = formData.enable_password;
            }

            if (formData.device_type === "fortinet" && formData.vdom) {
                credentials.vdom = formData.vdom;
            }

            const result = await dispatch(
                executeAudit({
                    deviceType: formData.device_type,
                    formData: credentials,
                })
            ).unwrap();

            onSubmit(result, formData.job_name);
        } catch (err) {
            setErrors({ submit: err || "Failed to start audit" });
        }
    };

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                {/* Two Column Grid */}
                <div className="form-grid-two-column">
                    {/* Device Type Selection */}
                    <div className="form-group form-group-full">
                        <label>Device Type <span className="required">*</span></label>
                        <select
                            name="device_type"
                            value={formData.device_type}
                            onChange={handleChange}
                            className="device-type-selector"
                        >
                            {deviceTypes.map((type) => (
                                <option
                                    key={type.value}
                                    value={type.value}
                                    disabled={!type.implemented}
                                >
                                    {type.label} {!type.implemented && "(Coming Soon)"}
                                </option>
                            ))}
                        </select>
                        {errors.device_type && <span className="error-message">{errors.device_type}</span>}
                    </div>

                    {/* Row 1 - Column 1 */}
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

                    {/* Row 1 - Column 2 */}
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

                    {/* Device-specific credential fields */}
                    {formData.device_type === "cisco" && (
                        <>
                            <div className="form-group">
                                <label>Username <span className="required">*</span></label>
                                <input
                                    type="text"
                                    name="ssh_username"
                                    value={formData.ssh_username}
                                    onChange={handleChange}
                                    className={errors.ssh_username ? "error" : ""}
                                    placeholder="SSH username"
                                />
                                {errors.ssh_username && <span className="error-message">{errors.ssh_username}</span>}
                            </div>

                            <div className="form-group">
                                <label>Enable Password</label>
                                <input
                                    type="password"
                                    name="enable_password"
                                    value={formData.enable_password}
                                    onChange={handleChange}
                                    placeholder="Enable password (optional)"
                                />
                            </div>

                            <div className="form-group form-group-full">
                                <label>Password <span className="required">*</span></label>
                                <input
                                    type="password"
                                    name="ssh_password"
                                    value={formData.ssh_password}
                                    onChange={handleChange}
                                    className={errors.ssh_password ? "error" : ""}
                                    placeholder="SSH password"
                                />
                                {errors.ssh_password && <span className="error-message">{errors.ssh_password}</span>}
                            </div>
                        </>
                    )}

                    {formData.device_type === "fortinet" && (
                        <>
                            <div className="form-group">
                                <label>Username <span className="required">*</span></label>
                                <input
                                    type="text"
                                    name="ssh_username"
                                    value={formData.ssh_username}
                                    onChange={handleChange}
                                    className={errors.ssh_username ? "error" : ""}
                                    placeholder="SSH username"
                                />
                                {errors.ssh_username && <span className="error-message">{errors.ssh_username}</span>}
                            </div>

                            <div className="form-group">
                                <label>VDOM (Optional)</label>
                                <input
                                    type="text"
                                    name="vdom"
                                    value={formData.vdom}
                                    onChange={handleChange}
                                    placeholder="Virtual Domain (leave empty for root)"
                                />
                            </div>

                            <div className="form-group form-group-full">
                                <label>Password <span className="required">*</span></label>
                                <input
                                    type="password"
                                    name="ssh_password"
                                    value={formData.ssh_password}
                                    onChange={handleChange}
                                    className={errors.ssh_password ? "error" : ""}
                                    placeholder="SSH password"
                                />
                                {errors.ssh_password && <span className="error-message">{errors.ssh_password}</span>}
                            </div>
                        </>
                    )}

                    {/* Coming soon message for unimplemented devices */}
                    {["linux", "windows", "apache"].includes(formData.device_type) && (
                        <div className="coming-soon-message">
                            <p>🚧 {deviceTypes.find(t => t.value === formData.device_type)?.label} auditing is coming soon!</p>
                            <p>Please select Cisco or FortiGate for now.</p>
                        </div>
                    )}
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
                        disabled={isExecuting}
                    >
                        cancel
                    </button>
                    <button
                        type="submit"
                        className="btn-submit"
                        disabled={isExecuting}
                    >
                        {isExecuting ? "Starting..." : "Next"}
                    </button>
                </div>
            </form>
        </div>
    );
};