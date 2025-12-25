// src/components/assets/AddAssetModal.jsx
import { useEffect, useState } from "react";
import { useDispatch } from "react-redux";
import { createAsset, fetchAssets } from "../../store/assetSlice";
import api from "../../config/api";

// فقط برای fallback (رشته‌ای)
const STATUS_FALLBACK = ["active", "standby", "decommissioned", "unknown"];
const CONFIDENTIALITY_FALLBACK = ["public", "internal", "confidential", "critical"];
const RISK_FALLBACK = ["low", "medium", "high", "critical"];

/**
 * هر ورودی enum رو تبدیل می‌کنیم به آرایه‌ای از:
 * [{ value: 'active', label: 'active' }, ...]
 * تا دیگه تو JSX هرگز به [object Object] برنخوریم.
 */
function mapEnumOptions(raw, fallbackArray) {
    let source = [];

    if (Array.isArray(raw) && raw.length > 0) {
        source = raw;
    } else {
        source = fallbackArray || [];
    }

    return source.map((item) => {
        // اگر رشته بود
        if (typeof item === "string") {
            return { value: item, label: item };
        }

        // اگر object بود (مثلاً { value, label } یا فرم‌های دیگه)
        if (item && typeof item === "object") {
            if ("value" in item && "label" in item) {
                return { value: String(item.value), label: String(item.label) };
            }

            const keys = Object.keys(item);
            const firstKey = keys[0] || "";
            const value =
                item.value ??
                item.key ??
                firstKey ??
                JSON.stringify(item);
            const label =
                item.label ??
                item.name ??
                item.title ??
                value;

            return { value: String(value), label: String(label) };
        }

        // سایر حالت‌ها
        return { value: String(item), label: String(item) };
    });
}

export const AddAssetModal = ({ isOpen, onClose }) => {
    const dispatch = useDispatch();

    const [currentStep, setCurrentStep] = useState(1);
    const [isLoadingOptions, setIsLoadingOptions] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);

    const [assetTypes, setAssetTypes] = useState([]);
    const [locations, setLocations] = useState([]);
    const [owners, setOwners] = useState([]);

    // این سه تا *همیشه* آرایه‌ای از {value,label} هستند
    const [statusOptions, setStatusOptions] = useState(
        () => mapEnumOptions(null, STATUS_FALLBACK)
    );
    const [confidentialityOptions, setConfidentialityOptions] = useState(
        () => mapEnumOptions(null, CONFIDENTIALITY_FALLBACK)
    );
    const [riskOptions, setRiskOptions] = useState(
        () => mapEnumOptions(null, RISK_FALLBACK)
    );

    const [formData, setFormData] = useState({
        asset_name: "",
        hostname: "",
        asset_type_id: "",
        asset_role: "",
        manufacturer: "",
        model: "",
        serial_number: "",
        os_name: "",
        os_version: "",
        ip_address: "",
        mac_address: "",
        location_id: "",
        owner_id: "",
        status: "active",
        confidentiality_level: "",
        risk_level: "",
        last_audit_date: "",
        last_patch_date: "",
        asset_value: "",
        description: ""
    });

    // وقتی مودال بسته میشه → همه چیز ریست
    const resetModal = () => {
        setCurrentStep(1);
        setError(null);
        setIsSubmitting(false);
        setFormData({
            asset_name: "",
            hostname: "",
            asset_type_id: "",
            asset_role: "",
            manufacturer: "",
            model: "",
            serial_number: "",
            os_name: "",
            os_version: "",
            ip_address: "",
            mac_address: "",
            location_id: "",
            owner_id: "",
            status: "active",
            confidentiality_level: "",
            risk_level: "",
            last_audit_date: "",
            last_patch_date: "",
            asset_value: "",
            description: ""
        });
    };

    useEffect(() => {
        if (!isOpen) {
            resetModal();
            return;
        }
        loadDropdownOptions();
    }, [isOpen]);

    // گرفتن options از API
    const loadDropdownOptions = async () => {
        setIsLoadingOptions(true);
        setError(null);

        try {
            const [
                typesRes,
                locsRes,
                ownersRes,
                statusRes,
                confRes,
                riskRes
            ] = await Promise.allSettled([
                api.get("/api/asset-types/"),
                api.get("/api/locations/"),
                api.get("/api/owners/"),
                api.get("/api/enums/status"),
                api.get("/api/enums/confidentiality"),
                api.get("/api/enums/risk")
            ]);

            // Asset Types
            if (typesRes.status === "fulfilled" && Array.isArray(typesRes.value.data)) {
                setAssetTypes(typesRes.value.data);
            } else {
                setAssetTypes([]);
            }

            // Locations
            if (locsRes.status === "fulfilled" && Array.isArray(locsRes.value.data)) {
                setLocations(locsRes.value.data);
            } else {
                setLocations([]);
            }

            // Owners
            if (ownersRes.status === "fulfilled" && Array.isArray(ownersRes.value.data)) {
                setOwners(ownersRes.value.data);
            } else {
                setOwners([]);
            }

            // Status (ممکنه آرایه string یا آرایه object باشه)
            let statusRaw = null;
            if (statusRes.status === "fulfilled") {
                statusRaw = statusRes.value.data;
                console.log("📊 Status API Response:", statusRaw);
            }
            setStatusOptions(mapEnumOptions(statusRaw, STATUS_FALLBACK));

            // Confidentiality
            let confRaw = null;
            if (confRes.status === "fulfilled") {
                confRaw = confRes.value.data;
                console.log("📊 Confidentiality API Response:", confRaw);
            }
            setConfidentialityOptions(
                mapEnumOptions(confRaw, CONFIDENTIALITY_FALLBACK)
            );

            // Risk
            let riskRaw = null;
            if (riskRes.status === "fulfilled") {
                riskRaw = riskRes.value.data;
                console.log("📊 Risk API Response:", riskRaw);
            }
            setRiskOptions(mapEnumOptions(riskRaw, RISK_FALLBACK));

        } catch (err) {
            console.error("Failed to load dropdown options:", err);
            setError("Failed to load form options. Some fields may be unavailable.");
        } finally {
            setIsLoadingOptions(false);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value
        }));
    };

    // Validation Step 1 (اسم و نوع اجباری)
    const validateStep1 = () => {
        if (!formData.asset_name.trim()) {
            setError("Asset Name is required");
            return false;
        }
        if (!formData.asset_type_id) {
            setError("Asset Type is required");
            return false;
        }
        setError(null);
        return true;
    };

    const handleNext = () => {
        console.log("📍 Current Step:", currentStep);

        if (currentStep === 1 && !validateStep1()) {
            console.log("🛑 Cannot proceed to next step");
            return;
        }

        setError(null);
        const nextStep = Math.min(currentStep + 1, 4);
        console.log("➡️ Moving to step:", nextStep);
        setCurrentStep(nextStep);
    };

    const handleBack = () => {
        setError(null);
        setCurrentStep((prev) => Math.max(prev - 1, 1));
    };

    const handleClose = () => {
        if (isSubmitting) return;
        onClose();
    };

    const handleSubmit = async () => {
        if (!validateStep1()) {
            setCurrentStep(1);
            return;
        }

        setError(null);
        setIsSubmitting(true);

        const payload = {
            asset_name: formData.asset_name.trim(),
            asset_type_id: Number(formData.asset_type_id),
            hostname: formData.hostname.trim() || null,
            asset_role: formData.asset_role.trim() || null,
            manufacturer: formData.manufacturer.trim() || null,
            model: formData.model.trim() || null,
            serial_number: formData.serial_number.trim() || null,
            os_name: formData.os_name.trim() || null,
            os_version: formData.os_version.trim() || null,
            ip_address: formData.ip_address.trim() || null,
            mac_address: formData.mac_address.trim() || null,
            location_id: formData.location_id ? Number(formData.location_id) : null,
            owner_id: formData.owner_id ? Number(formData.owner_id) : null,
            status: formData.status || "active",
            confidentiality_level: formData.confidentiality_level || null,
            risk_level: formData.risk_level || null,
            last_audit_date: formData.last_audit_date || null,
            last_patch_date: formData.last_patch_date || null,
            asset_value: formData.asset_value ? Number(formData.asset_value) : null,
            description: formData.description.trim() || null
        };

        try {
            await dispatch(createAsset(payload)).unwrap();
            dispatch(fetchAssets());
            onClose();
        } catch (err) {
            console.error("Failed to create asset:", err);
            setError(
                typeof err === "string"
                    ? err
                    : "Failed to create asset. Please try again."
            );
        } finally {
            setIsSubmitting(false);
        }
    };

    if (!isOpen) return null;

    const renderStepContent = () => {
        switch (currentStep) {
            case 1:
                return (
                    <div className="form-grid">
                        <div className="form-group">
                            <label>
                                Asset Name <span className="required">*</span>
                            </label>
                            <input
                                type="text"
                                name="asset_name"
                                value={formData.asset_name}
                                onChange={handleChange}
                                placeholder="e.g. Web Server 01"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>Hostname</label>
                            <input
                                type="text"
                                name="hostname"
                                value={formData.hostname}
                                onChange={handleChange}
                                placeholder="e.g. web01.local"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>
                                Asset Type <span className="required">*</span>
                            </label>
                            <select
                                name="asset_type_id"
                                value={formData.asset_type_id}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            >
                                <option value="">Select type</option>
                                {assetTypes.map((type) => (
                                    <option key={type.id} value={type.id}>
                                        {type.type_name}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Role</label>
                            <input
                                type="text"
                                name="asset_role"
                                value={formData.asset_role}
                                onChange={handleChange}
                                placeholder="e.g. Application Server"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>Manufacturer</label>
                            <input
                                type="text"
                                name="manufacturer"
                                value={formData.manufacturer}
                                onChange={handleChange}
                                placeholder="e.g. Dell, HP, Cisco"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>Model</label>
                            <input
                                type="text"
                                name="model"
                                value={formData.model}
                                onChange={handleChange}
                                placeholder="e.g. R740"
                                disabled={isLoadingOptions}
                            />
                        </div>
                    </div>
                );

            case 2:
                return (
                    <div className="form-grid">
                        <div className="form-group">
                            <label>Serial Number</label>
                            <input
                                type="text"
                                name="serial_number"
                                value={formData.serial_number}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>OS Name</label>
                            <input
                                type="text"
                                name="os_name"
                                value={formData.os_name}
                                onChange={handleChange}
                                placeholder="e.g. Windows Server, Ubuntu"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>OS Version</label>
                            <input
                                type="text"
                                name="os_version"
                                value={formData.os_version}
                                onChange={handleChange}
                                placeholder="e.g. 22.04, 2019"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>IP Address</label>
                            <input
                                type="text"
                                name="ip_address"
                                value={formData.ip_address}
                                onChange={handleChange}
                                placeholder="e.g. 192.168.1.10"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>MAC Address</label>
                            <input
                                type="text"
                                name="mac_address"
                                value={formData.mac_address}
                                onChange={handleChange}
                                placeholder="e.g. 00:1A:2B:3C:4D:5E"
                                disabled={isLoadingOptions}
                            />
                        </div>
                    </div>
                );

            case 3:
                return (
                    <div className="form-grid">
                        <div className="form-group">
                            <label>Location</label>
                            <select
                                name="location_id"
                                value={formData.location_id}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            >
                                <option value="">Select location</option>
                                {locations.map((loc) => (
                                    <option key={loc.id} value={loc.id}>
                                        {loc.site_name}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Owner</label>
                            <select
                                name="owner_id"
                                value={formData.owner_id}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            >
                                <option value="">Select owner</option>
                                {owners.map((owner) => (
                                    <option key={owner.id} value={owner.id}>
                                        {owner.full_name}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Status</label>
                            <select
                                name="status"
                                value={formData.status}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            >
                                {statusOptions.map((opt) => (
                                    <option key={opt.value} value={opt.value}>
                                        {opt.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>
                );

            case 4:
                return (
                    <div className="form-grid">
                        <div className="form-group">
                            <label>Confidentiality Level</label>
                            <select
                                name="confidentiality_level"
                                value={formData.confidentiality_level}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            >
                                <option value="">Select level</option>
                                {confidentialityOptions.map((opt) => (
                                    <option key={opt.value} value={opt.value}>
                                        {opt.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Risk Level</label>
                            <select
                                name="risk_level"
                                value={formData.risk_level}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            >
                                <option value="">Select level</option>
                                {riskOptions.map((opt) => (
                                    <option key={opt.value} value={opt.value}>
                                        {opt.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Last Audit Date</label>
                            <input
                                type="date"
                                name="last_audit_date"
                                value={formData.last_audit_date}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>Last Patch Date</label>
                            <input
                                type="date"
                                name="last_patch_date"
                                value={formData.last_patch_date}
                                onChange={handleChange}
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group">
                            <label>Asset Value</label>
                            <input
                                type="number"
                                name="asset_value"
                                value={formData.asset_value}
                                onChange={handleChange}
                                min="0"
                                disabled={isLoadingOptions}
                            />
                        </div>
                        <div className="form-group full-width">
                            <label>Description</label>
                            <textarea
                                name="description"
                                value={formData.description}
                                onChange={handleChange}
                                rows="3"
                                placeholder="Optional notes about this asset"
                                disabled={isLoadingOptions}
                            />
                        </div>
                    </div>
                );

            default:
                return null;
        }
    };

    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div
                className="modal-content modal-large"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="modal-header">
                    <h3>Add New Asset</h3>
                    <button
                        className="modal-close"
                        onClick={handleClose}
                        disabled={isSubmitting}
                    >
                        ✕
                    </button>
                </div>

                <div className="modal-body">
                    <div className="step-indicator">
                        <div className={`step ${currentStep >= 1 ? "active" : ""}`}>
                            1. Basic Info
                        </div>
                        <div className={`step ${currentStep >= 2 ? "active" : ""}`}>
                            2. System
                        </div>
                        <div className={`step ${currentStep >= 3 ? "active" : ""}`}>
                            3. Location
                        </div>
                        <div className={`step ${currentStep >= 4 ? "active" : ""}`}>
                            4. Security
                        </div>
                    </div>

                    {isLoadingOptions && (
                        <div className="loading-spinner">Loading form options...</div>
                    )}

                    {!isLoadingOptions && renderStepContent()}

                    {error && (
                        <div className="alert alert-error" style={{ marginTop: "12px" }}>
                            {error}
                        </div>
                    )}
                </div>

                <div className="modal-actions">
                    <button
                        className="btn-cancel"
                        onClick={handleClose}
                        disabled={isSubmitting}
                    >
                        Cancel
                    </button>

                    {currentStep > 1 && (
                        <button
                            className="btn-secondary"
                            onClick={handleBack}
                            disabled={isSubmitting || isLoadingOptions}
                        >
                            Back
                        </button>
                    )}

                    {currentStep < 4 && (
                        <button
                            className="btn-submit"
                            onClick={handleNext}
                            disabled={isSubmitting || isLoadingOptions}
                        >
                            Next
                        </button>
                    )}

                    {currentStep === 4 && (
                        <button
                            className="btn-submit"
                            onClick={handleSubmit}
                            disabled={isSubmitting || isLoadingOptions}
                        >
                            {isSubmitting ? "Creating..." : "Create Asset"}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
};
