import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";

export const EditAssetModal = ({ asset, onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        asset_name: asset.asset_name || "",
        hostname: asset.hostname || "",
        asset_type_id: asset.asset_type_id || "",
        asset_role: asset.asset_role || "",
        manufacturer: asset.manufacturer || "",
        model: asset.model || "",
        serial_number: asset.serial_number || "",
        os_name: asset.os_name || "",
        os_version: asset.os_version || "",
        ip_address: asset.ip_address || "",
        mac_address: asset.mac_address || "",
        location_id: asset.location_id || "",
        owner_id: asset.owner_id || "",
        status: asset.status || "active",
        confidentiality_level: asset.confidentiality_level || "",
        risk_level: asset.risk_level || "",
        last_audit_date: asset.last_audit_date || "",
        last_patch_date: asset.last_patch_date || "",
        asset_value: asset.asset_value || "",
        description: asset.description || "",
    });

    const [activeTab, setActiveTab] = useState("basic");

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value,
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        // فقط فیلدهای تغییر یافته رو بفرست
        const updateData = {};
        Object.keys(formData).forEach((key) => {
            if (formData[key] !== asset[key]) {
                // اگر مقدار خالی نیست یا null نیست
                if (formData[key] !== "" && formData[key] !== null) {
                    updateData[key] = formData[key];
                }
            }
        });

        console.log("Updating asset with:", updateData);

        const result = await dispatch(updateAsset({
            assetId: asset.id,
            assetData: updateData
        }));

        if (result.type === "assets/update/fulfilled") {
            dispatch(fetchAssets());
            onClose();
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Edit Asset: {asset.asset_name}</h3>
                    <button className="modal-close" onClick={onClose}>✕</button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        {/* Tabs for organizing fields */}
                        <div className="modal-tabs">
                            <div
                                className={`modal-tab ${activeTab === "basic" ? "active" : ""}`}
                                onClick={() => setActiveTab("basic")}
                            >
                                Basic Info
                            </div>
                            <div
                                className={`modal-tab ${activeTab === "network" ? "active" : ""}`}
                                onClick={() => setActiveTab("network")}
                            >
                                Network
                            </div>
                            <div
                                className={`modal-tab ${activeTab === "location" ? "active" : ""}`}
                                onClick={() => setActiveTab("location")}
                            >
                                Location
                            </div>
                            <div
                                className={`modal-tab ${activeTab === "security" ? "active" : ""}`}
                                onClick={() => setActiveTab("security")}
                            >
                                Security
                            </div>
                        </div>

                        {/* Basic Info Tab */}
                        {activeTab === "basic" && (
                            <>
                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Asset Name *</label>
                                        <input
                                            type="text"
                                            name="asset_name"
                                            value={formData.asset_name}
                                            onChange={handleChange}
                                            required
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Hostname</label>
                                        <input
                                            type="text"
                                            name="hostname"
                                            value={formData.hostname}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Type ID</label>
                                        <input
                                            type="number"
                                            name="asset_type_id"
                                            value={formData.asset_type_id}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Role</label>
                                        <input
                                            type="text"
                                            name="asset_role"
                                            value={formData.asset_role}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Manufacturer</label>
                                        <input
                                            type="text"
                                            name="manufacturer"
                                            value={formData.manufacturer}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Model</label>
                                        <input
                                            type="text"
                                            name="model"
                                            value={formData.model}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Serial Number</label>
                                        <input
                                            type="text"
                                            name="serial_number"
                                            value={formData.serial_number}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Status</label>
                                        <select
                                            name="status"
                                            value={formData.status}
                                            onChange={handleChange}
                                        >
                                            <option value="active">Active</option>
                                            <option value="standby">Standby</option>
                                            <option value="decommissioned">Decommissioned</option>
                                            <option value="unknown">Unknown</option>
                                        </select>
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Network Tab */}
                        {activeTab === "network" && (
                            <>
                                <div className="form-row">
                                    <div className="form-group">
                                        <label>OS Name</label>
                                        <input
                                            type="text"
                                            name="os_name"
                                            value={formData.os_name}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>OS Version</label>
                                        <input
                                            type="text"
                                            name="os_version"
                                            value={formData.os_version}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>IP Address</label>
                                        <input
                                            type="text"
                                            name="ip_address"
                                            value={formData.ip_address}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>MAC Address</label>
                                        <input
                                            type="text"
                                            name="mac_address"
                                            value={formData.mac_address}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Location Tab */}
                        {activeTab === "location" && (
                            <>
                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Location ID</label>
                                        <input
                                            type="number"
                                            name="location_id"
                                            value={formData.location_id}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Owner ID</label>
                                        <input
                                            type="number"
                                            name="owner_id"
                                            value={formData.owner_id}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Security Tab */}
                        {activeTab === "security" && (
                            <>
                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Confidentiality Level</label>
                                        <select
                                            name="confidentiality_level"
                                            value={formData.confidentiality_level}
                                            onChange={handleChange}
                                        >
                                            <option value="">-</option>
                                            <option value="public">Public</option>
                                            <option value="internal">Internal</option>
                                            <option value="confidential">Confidential</option>
                                            <option value="critical">Critical</option>
                                        </select>
                                    </div>
                                    <div className="form-group">
                                        <label>Risk Level</label>
                                        <select
                                            name="risk_level"
                                            value={formData.risk_level}
                                            onChange={handleChange}
                                        >
                                            <option value="">-</option>
                                            <option value="low">Low</option>
                                            <option value="medium">Medium</option>
                                            <option value="high">High</option>
                                            <option value="critical">Critical</option>
                                        </select>
                                    </div>
                                </div>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Last Audit Date</label>
                                        <input
                                            type="date"
                                            name="last_audit_date"
                                            value={formData.last_audit_date}
                                            onChange={handleChange}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Last Patch Date</label>
                                        <input
                                            type="date"
                                            name="last_patch_date"
                                            value={formData.last_patch_date}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Asset Value</label>
                                        <input
                                            type="number"
                                            name="asset_value"
                                            value={formData.asset_value}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Description (همیشه نمایش داده میشه) */}
                        <div className="form-row">
                            <div className="form-group full-width">
                                <label>Description</label>
                                <textarea
                                    name="description"
                                    value={formData.description}
                                    onChange={handleChange}
                                    rows="3"
                                />
                            </div>
                        </div>
                    </div>

                    <div className="modal-actions">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                            Cancel
                        </button>
                        <button type="submit" className="btn-submit">
                            Update
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};