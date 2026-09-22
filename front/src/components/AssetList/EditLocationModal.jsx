import { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";
import { useAssetFormOptions } from "./useAssetFormOptions";
import { requiresHosting } from "../shared/assetHosting";

export const EditLocationModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { isLoading, locations, owners, statusOptions, assetTypes } = useAssetFormOptions();
    const existingAssets = useSelector((state) => state.assets.assets);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [fieldErrors, setFieldErrors] = useState({});
    const [formData, setFormData] = useState({
        location_id: asset.location_id ?? "",
        owner_id: asset.owner_id ?? "",
        hosted_on_asset_id: asset.hosted_on_asset_id ?? "",
        hosted_vlan: asset.hosted_vlan ?? "",
        status: asset.status ?? "active"
    });

    const selectedTypeName = assetTypes.find(t => String(t.id) === String(asset.asset_type_id))?.type_name;
    const hostingRequired = requiresHosting(selectedTypeName);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (hostingRequired && !formData.hosted_on_asset_id) {
            setFieldErrors({ hosted_on_asset_id: `${selectedTypeName} must specify which server it's hosted on` });
            return;
        }
        setFieldErrors({});
        setIsSubmitting(true);
        setError(null);
        try {
            const submitData = { ...formData };
            // Empty-string selects (e.g. "Select location") mean "unset" -
            // send null, not "", which Optional[int] fields would reject.
            Object.keys(submitData).forEach(key => { if (submitData[key] === "") submitData[key] = null; });
            if (submitData.hosted_on_asset_id !== null) submitData.hosted_on_asset_id = Number(submitData.hosted_on_asset_id);

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
                    <h3>Edit Location - {asset.asset_name}</h3>
                    <button className="modal-close" onClick={onClose} disabled={isSubmitting}>✕</button>
                </div>
                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        {isLoading && <div className="loading-spinner">Loading...</div>}
                        {!isLoading && (
                            <div className="form-grid">
                                <div className="form-group">
                                    <label>Location</label>
                                    <select name="location_id" value={formData.location_id} onChange={handleChange} disabled={isSubmitting}>
                                        <option value="">Select location</option>
                                        {locations.map((loc) => (<option key={loc.id} value={loc.id}>{loc.site_name || loc.location_name || `Location ${loc.id}`}</option>))}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Owner</label>
                                    <select name="owner_id" value={formData.owner_id} onChange={handleChange} disabled={isSubmitting}>
                                        <option value="">Select owner</option>
                                        {owners.map((owner) => (<option key={owner.id} value={owner.id}>{owner.full_name}</option>))}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Status</label>
                                    <select name="status" value={formData.status} onChange={handleChange} disabled={isSubmitting}>
                                        {statusOptions.map((opt) => (<option key={opt.value} value={opt.value}>{opt.label}</option>))}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Hosted on server{hostingRequired && <span className="required"> *</span>}</label>
                                    <select
                                        name="hosted_on_asset_id"
                                        value={formData.hosted_on_asset_id}
                                        onChange={handleChange}
                                        disabled={isSubmitting}
                                        style={fieldErrors.hosted_on_asset_id ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                                    >
                                        <option value="">Select server</option>
                                        {existingAssets.filter((a) => a.id !== asset.id).map((a) => (
                                            <option key={a.id} value={a.id}>{a.asset_name}</option>
                                        ))}
                                    </select>
                                    {fieldErrors.hosted_on_asset_id && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.hosted_on_asset_id}</span>}
                                    {hostingRequired && !fieldErrors.hosted_on_asset_id && (
                                        <span style={{ display: 'block', color: '#6c757d', fontSize: '11px', marginTop: '3px' }}>
                                            {selectedTypeName} runs inside a server - Topology draws a dashed line to it.
                                        </span>
                                    )}
                                </div>
                                <div className="form-group">
                                    <label>VLAN</label>
                                    <input
                                        type="text"
                                        name="hosted_vlan"
                                        value={formData.hosted_vlan}
                                        onChange={handleChange}
                                        placeholder="e.g. 110"
                                        disabled={isSubmitting}
                                    />
                                    <span style={{ display: "block", color: "#6c757d", fontSize: "11px", marginTop: "3px" }}>
                                        Shown as a label on the dashed line to the hosting server.
                                    </span>
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