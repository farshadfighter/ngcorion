import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";
import { useAssetFormOptions } from "./useAssetFormOptions";

// Validation functions
const validateAssetName = (name) => {
    if (!name || name.trim().length < 2) {
        return { valid: false, error: 'Asset name must be at least 2 characters' };
    }
    return { valid: true };
};

export const EditOverviewModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { isLoading, assetTypes, vendors, zones } = useAssetFormOptions();
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [fieldErrors, setFieldErrors] = useState({});
    const [formData, setFormData] = useState({
        asset_name: asset.asset_name || "",
        hostname: asset.hostname || "",
        asset_type_id: asset.asset_type_id || "",
        asset_role: asset.asset_role || "",
        manufacturer: asset.manufacturer || "",
        model: asset.model || ""
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
        const nameCheck = validateAssetName(formData.asset_name);
        if (!nameCheck.valid) errors.asset_name = nameCheck.error;
        if (!formData.asset_type_id) errors.asset_type_id = "Asset Type is required";
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
            Object.keys(submitData).forEach(key => { if (submitData[key] === "") submitData[key] = null; });

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
                    <h3>Edit Overview - {asset.asset_name}</h3>
                    <button className="modal-close" onClick={onClose} disabled={isSubmitting}>✕</button>
                </div>
                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        {isLoading && <div className="loading-spinner">Loading...</div>}
                        {!isLoading && (
                            <div className="form-grid">
                                <div className="form-group">
                                    <label>Asset Name <span className="required">*</span></label>
                                    <input
                                        type="text"
                                        name="asset_name"
                                        value={formData.asset_name}
                                        onChange={handleChange}
                                        required
                                        disabled={isSubmitting}
                                        style={fieldErrors.asset_name ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                                    />
                                    {fieldErrors.asset_name && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.asset_name}</span>}
                                </div>
                                <div className="form-group">
                                    <label>Hostname</label>
                                    <input type="text" name="hostname" value={formData.hostname} onChange={handleChange} disabled={isSubmitting} />
                                </div>
                                <div className="form-group">
                                    <label>Asset Type <span className="required">*</span></label>
                                    <select
                                        name="asset_type_id"
                                        value={formData.asset_type_id}
                                        onChange={handleChange}
                                        required
                                        disabled={isSubmitting}
                                        style={fieldErrors.asset_type_id ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                                    >
                                        <option value="">Select type</option>
                                        {assetTypes.map((type) => (<option key={type.id} value={type.id}>{type.type_name}</option>))}
                                    </select>
                                    {fieldErrors.asset_type_id && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.asset_type_id}</span>}
                                </div>
                                <div className="form-group">
                                    <label>Network Zone</label>
                                    <select name="asset_role" value={formData.asset_role} onChange={handleChange} disabled={isSubmitting}>
                                        <option value="">Select zone</option>
                                        {zones.map((zone) => (<option key={zone.id} value={zone.zone_name}>{zone.zone_name}</option>))}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Vendor</label>
                                    <select name="manufacturer" value={formData.manufacturer} onChange={handleChange} disabled={isSubmitting}>
                                        <option value="">Select vendor</option>
                                        {vendors.map((vendor) => (<option key={vendor.id} value={vendor.vendor_name}>{vendor.vendor_name}</option>))}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Model</label>
                                    <input type="text" name="model" value={formData.model} onChange={handleChange} disabled={isSubmitting} />
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