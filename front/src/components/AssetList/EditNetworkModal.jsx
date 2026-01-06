import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";

export const EditNetworkModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [formData, setFormData] = useState({
        serial_number: asset.serial_number || "",
        os_name: asset.os_name || "",
        ip_address: asset.ip_address || "",
        mac_address: asset.mac_address || ""
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
                    <h3>Edit Network - {asset.asset_name}</h3>
                    <button className="modal-close" onClick={onClose} disabled={isSubmitting}>✕</button>
                </div>
                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        <div className="form-grid">
                            <div className="form-group">
                                <label>Serial Number</label>
                                <input type="text" name="serial_number" value={formData.serial_number} onChange={handleChange} placeholder="e.g. SN123456789" disabled={isSubmitting} />
                            </div>
                            <div className="form-group">
                                <label>Operating System</label>
                                <input type="text" name="os_name" value={formData.os_name} onChange={handleChange} placeholder="e.g. Ubuntu 22.04" disabled={isSubmitting} />
                            </div>
                            <div className="form-group">
                                <label>IP Address</label>
                                <input type="text" name="ip_address" value={formData.ip_address} onChange={handleChange} placeholder="e.g. 192.168.1.10" disabled={isSubmitting} />
                            </div>
                            <div className="form-group">
                                <label>MAC Address</label>
                                <input type="text" name="mac_address" value={formData.mac_address} onChange={handleChange} placeholder="e.g. 00:1A:2B:3C:4D:5E" disabled={isSubmitting} />
                            </div>
                        </div>
                        {error && <div className="alert alert-error" style={{ marginTop: "12px" }}>{error}</div>}
                    </div>
                    <div className="modal-actions">
                        <button type="button" className="btn-cancel" onClick={onClose} disabled={isSubmitting}>Cancel</button>
                        <button type="submit" className="btn-submit" disabled={isSubmitting}>{isSubmitting ? "Updating..." : "Update"}</button>
                    </div>
                </form>
            </div>
        </div>
    );
};