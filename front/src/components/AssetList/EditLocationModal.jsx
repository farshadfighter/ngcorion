import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";
import { useAssetFormOptions } from "./useAssetFormOptions";

export const EditLocationModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { isLoading, locations, owners, statusOptions } = useAssetFormOptions();
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [formData, setFormData] = useState({
        location_id: asset.location_id || "",
        owner_id: asset.owner_id || "",
        status: asset.status || "active"
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