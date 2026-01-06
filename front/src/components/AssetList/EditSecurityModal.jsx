import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";
import { useAssetFormOptions } from "./useAssetFormOptions";

export const EditSecurityModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { isLoading, confidentialityOptions, riskOptions } = useAssetFormOptions();
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [formData, setFormData] = useState({
        confidentiality_level: asset.confidentiality_level || "",
        risk_level: asset.risk_level || "",
        last_audit_date: asset.last_audit_date || "",
        last_patch_date: asset.last_patch_date || "",
        asset_value: asset.asset_value || "",
        description: asset.description || ""
    });

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setError(null);
        try {
            const submitData = { ...formData };
            Object.keys(submitData).forEach(key => {
                if (submitData[key] === "") submitData[key] = null;
            });
            const result = await dispatch(updateAsset({ assetId: asset.id, assetData: submitData }));
            if (result.type === "assets/update/fulfilled") {
                await dispatch(fetchAssets());
                onClose();
            } else {
                let errorMessage = "Failed to update asset";
                if (result.payload) {
                    if (Array.isArray(result.payload)) {
                        errorMessage = result.payload.map(err => `${err.loc?.join('.') || 'field'}: ${err.msg}`).join(' | ');
                    } else if (typeof result.payload === 'string') {
                        errorMessage = result.payload;
                    } else if (result.payload.detail) {
                        if (Array.isArray(result.payload.detail)) {
                            errorMessage = result.payload.detail.map(err => `${err.loc?.join('.') || 'field'}: ${err.msg}`).join(' | ');
                        } else {
                            errorMessage = typeof result.payload.detail === 'string' ? result.payload.detail : JSON.stringify(result.payload.detail);
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
                                        <input type="number" name="asset_value" value={formData.asset_value} onChange={handleChange} min="0" step="0.01" placeholder="0.00" disabled={isSubmitting} className="input-with-prefix" />
                                    </div>
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