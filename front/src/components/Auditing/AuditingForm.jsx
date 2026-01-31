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
        enable_password: "",
    });

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

        if (!validate()) {
            return;
        }

        try {
            const result = await dispatch(
                executeAudit({
                    deviceType: formData.device_type,
                    formData: {
                        asset_id: parseInt(formData.asset_id),
                        ssh_username: formData.ssh_username,
                        ssh_password: formData.ssh_password,
                        ssh_secret: formData.enable_password || null,
                    },
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
                <input type="hidden" name="device_type" value={formData.device_type} />

                {/* Two Column Grid */}
                <div className="form-grid-two-column">
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

                    {/* Row 2 - Column 1 */}
                    <div className="form-group">
                        <label>UserName <span className="required">*</span></label>
                        <input
                            type="text"
                            name="ssh_username"
                            value={formData.ssh_username}
                            onChange={handleChange}
                            className={errors.ssh_username ? "error" : ""}
                            placeholder="Enter SSH username"
                        />
                        {errors.ssh_username && <span className="error-message">{errors.ssh_username}</span>}
                    </div>

                    {/* Row 2 - Column 2 */}
                    <div className="form-group">
                        <label>Enable Password</label>
                        <input
                            type="password"
                            name="enable_password"
                            value={formData.enable_password}
                            onChange={handleChange}
                            placeholder="Enter enable password (optional)"
                        />
                    </div>

                    {/* Row 3 - Full Width */}
                    <div className="form-group form-group-full">
                        <label>Password <span className="required">*</span></label>
                        <input
                            type="password"
                            name="ssh_password"
                            value={formData.ssh_password}
                            onChange={handleChange}
                            className={errors.ssh_password ? "error" : ""}
                            placeholder="Enter SSH password"
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