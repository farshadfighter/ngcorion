import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";
import { useAssetFormOptions } from "./useAssetFormOptions";

// Validation function
const validateAssetValue = (value) => {
    if (value !== null && value !== '' && parseFloat(value) < 0) {
        return { valid: false, error: 'Asset value must be positive' };
    }
    return { valid: true };
};

export const EditSecurityModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { isLoading, confidentialityOptions, riskOptions } = useAssetFormOptions();
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [fieldErrors, setFieldErrors] = useState({});
    const [formData, setFormData] = useState({
        confidentiality_level: asset.confidentiality_level || "",
        risk_level: asset.risk_level ?? "",
        last_audit_date: asset.last_audit_date ?? "",
        last_patch_date: asset.last_patch_date ?? "",
        asset_value: asset.asset_value ?? "",
        description: asset.description ?? ""
    });

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (fieldErrors[name]) {
            setFieldErrors(prev => {
                const newErrors = { ...prev };
                delete newErrors[name];
                return newErrors;
            });
        }
    };

    const validateForm = () => {
        const errors = {};
        const valueCheck = validateAssetValue(formData.asset_value);
        if (!valueCheck.valid) errors.asset_value = valueCheck.error;
        setFieldErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!validateForm()) return;

        setIsSubmitting(true);
        setError(null);
        try {
            const submitData = { ...formData };

            const result = await dispatch(updateAsset({ assetId: asset.id, assetData: submitData }));

            if (result.type === "assets/update/fulfilled") {
                await dispatch(fetchAssets());
                onClose();
            } else {
                let errorMessage = "Failed to update asset";

                if (result.payload) {
                    if (typeof result.payload === 'string') {
                        if (result.payload.includes('duplicate key') || result.payload.includes('UniqueViolation')) {
                            errorMessage = 'A duplicate value was detected. Please check your inputs.';
                        } else {
                            errorMessage = result.payload;
                        }
                    } else if (Array.isArray(result.payload)) {
                        errorMessage = result.payload.map(err => `${err.loc?.join('.') || 'field'}: ${err.msg}`).join(' | ');
                    } else if (result.payload.detail) {
                        const detail = result.payload.detail;
                        if (typeof detail === 'string' && (detail.includes('duplicate key') || detail.includes('UniqueViolation'))) {
                            errorMessage = 'A duplicate value was detected. Please check your inputs.';
                        } else if (Array.isArray(detail)) {
                            errorMessage = detail.map(err => `${err.loc?.join('.') || 'field'}: ${err.msg}`).join(' | ');
                        } else {
                            errorMessage = typeof detail === 'string' ? detail : JSON.stringify(detail);
                        }
                    } else {
                        errorMessage = JSON.stringify(result.payload);
                    }
                }
                setError(errorMessage);
            }
        } catch (err) {
            setError(err.message || "An unexpected error occurred");
        } finally {
            setIsSubmitting(false);
        }
    };

    if (!isOpen) return null;
    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content2 modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Edit Security - {asset.asset_name}</h3>
                    <button className="modal-close" onClick={onClose} disabled={isSubmitting}>✕</button>
                </div>
                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        {isLoading && <div className="loading-spinner">Loading...</div>}
                        {!isLoading && (
                            <div className="form-grid">
                                <div className="form-group">
                                    <label>Confidentiality Level</label>
                                    <select name="confidentiality_level" value={formData.confidentiality_level} onChange={handleChange} disabled={isSubmitting}>
                                        <option value="">Select level</option>
                                        {confidentialityOptions.map((opt) => (<option key={opt.value} value={opt.value}>{opt.label}</option>))}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Risk Level</label>
                                    <select name="risk_level" value={formData.risk_level} onChange={handleChange} disabled={isSubmitting}>
                                        <option value="">Select level</option>
                                        {riskOptions.map((opt) => (<option key={opt.value} value={opt.value}>{opt.label}</option>))}
                                        {/* An asset saved before very_high was withdrawn keeps its value:
                                            without this the select would silently fall back to "Select
                                            level" and a plain Save would rewrite the asset's risk level. */}
                                        {formData.risk_level &&
                                            !riskOptions.some((opt) => opt.value === formData.risk_level) && (
                                            <option value={formData.risk_level}>
                                                {String(formData.risk_level).replace(/_/g, " ")} (not scored)
                                            </option>
                                        )}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Last Audit Date</label>
                                    <input type="date" name="last_audit_date" value={formData.last_audit_date} onChange={handleChange} disabled={isSubmitting} />
                                </div>
                                <div className="form-group">
                                    <label>Last Patch Date</label>
                                    <input type="date" name="last_patch_date" value={formData.last_patch_date} onChange={handleChange} disabled={isSubmitting} />
                                </div>
                                <div className="form-group">
                                    <label>Asset Value (USD)</label>
                                    <div className="input-with-icon">
                                        <span className="input-icon">$</span>
                                        <input
                                            type="number"
                                            name="asset_value"
                                            value={formData.asset_value}
                                            onChange={handleChange}
                                            min="0"
                                            step="0.01"
                                            placeholder="0.00"
                                            disabled={isSubmitting}
                                            className="input-with-prefix"
                                            style={fieldErrors.asset_value ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                                        />
                                    </div>
                                    {fieldErrors.asset_value && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.asset_value}</span>}
                                </div>
                                <div className="form-group full-width">
                                    <label>Description</label>
                                    <textarea name="description" value={formData.description} onChange={handleChange} rows="3" placeholder="Optional notes" disabled={isSubmitting} />
                                </div>
                            </div>
                        )}
                        {error && <div className="alert alert-error" style={{ marginTop: "12px" }}>{error}</div>}
                    </div>
                    <div className="modal-actions">
                        <button type="button" className="btn-cancel" onClick={onClose} disabled={isSubmitting}>Cancel</button>
                        <button type="submit" className="btn-submit" disabled={isSubmitting || isLoading}>{isSubmitting ? "Updating..." : "Update"}</button>
                    </div>
                </form>
            </div>
        </div>
    );
};