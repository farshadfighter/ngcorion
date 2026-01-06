// AddAssetModal.jsx - CLEAN VERSION
import { useEffect, useState } from "react";
import { useDispatch } from "react-redux";
import { createAsset, fetchAssets } from "../../store/assetSlice";
import api from "../../config/api";

const STATUS_FALLBACK = ["active", "standby", "decommissioned", "unknown"];
const CONFIDENTIALITY_FALLBACK = ["public", "internal", "confidential", "critical"];
const RISK_FALLBACK = ["low", "medium", "high", "critical"];

function mapEnumOptions(raw, fallbackArray) {
    let source = Array.isArray(raw) && raw.length > 0 ? raw : (fallbackArray || []);
    return source.map((item) => {
        if (typeof item === "string") return { value: item, label: item };
        if (item && typeof item === "object") {
            if ("value" in item && "label" in item) return { value: String(item.value), label: String(item.label) };
            const keys = Object.keys(item);
            const value = item.value ?? item.key ?? keys[0] ?? JSON.stringify(item);
            const label = item.label ?? item.name ?? item.title ?? value;
            return { value: String(value), label: String(label) };
        }
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
    const [zones, setZones] = useState([]);
    const [vendors, setVendors] = useState([]);
    const [statusOptions, setStatusOptions] = useState(() => mapEnumOptions(null, STATUS_FALLBACK));
    const [confidentialityOptions, setConfidentialityOptions] = useState(() => mapEnumOptions(null, CONFIDENTIALITY_FALLBACK));
    const [riskOptions, setRiskOptions] = useState(() => mapEnumOptions(null, RISK_FALLBACK));
    const [formData, setFormData] = useState({
        asset_name: "", hostname: "", asset_type_id: "", asset_role: "", manufacturer: "", model: "",
        serial_number: "", os_name: "", os_version: "", ip_address: "", mac_address: "", location_id: "",
        owner_id: "", status: "active", confidentiality_level: "", risk_level: "", last_audit_date: "",
        last_patch_date: "", asset_value: "", description: ""
    });

    const resetModal = () => {
        setCurrentStep(1);
        setError(null);
        setIsSubmitting(false);
        setFormData({
            asset_name: "", hostname: "", asset_type_id: "", asset_role: "", manufacturer: "", model: "",
            serial_number: "", os_name: "", os_version: "", ip_address: "", mac_address: "", location_id: "",
            owner_id: "", status: "active", confidentiality_level: "", risk_level: "", last_audit_date: "",
            last_patch_date: "", asset_value: "", description: ""
        });
    };

    useEffect(() => {
        if (!isOpen) { resetModal(); return; }
        loadDropdownOptions();
    }, [isOpen]);

    const loadDropdownOptions = async () => {
        setIsLoadingOptions(true);
        setError(null);
        try {
            const [typesRes, locsRes, ownersRes, zonesRes, vendorsRes, statusRes, confRes, riskRes] = await Promise.allSettled([
                api.get("/api/asset-types/"), api.get("/api/locations/"), api.get("/api/owners/"),
                api.get("/api/zones/"), api.get("/api/vendors/"), api.get("/api/enums/status"),
                api.get("/api/enums/confidentiality"), api.get("/api/enums/risk")
            ]);
            setAssetTypes(typesRes.status === "fulfilled" && Array.isArray(typesRes.value.data) ? typesRes.value.data : []);
            setLocations(locsRes.status === "fulfilled" && Array.isArray(locsRes.value.data) ? locsRes.value.data : []);
            setOwners(ownersRes.status === "fulfilled" && Array.isArray(ownersRes.value.data) ? ownersRes.value.data : []);
            setZones(zonesRes.status === "fulfilled" && Array.isArray(zonesRes.value.data) ? zonesRes.value.data : []);
            setVendors(vendorsRes.status === "fulfilled" && Array.isArray(vendorsRes.value.data) ? vendorsRes.value.data : []);
            setStatusOptions(mapEnumOptions(statusRes.status === "fulfilled" ? statusRes.value.data : null, STATUS_FALLBACK));
            setConfidentialityOptions(mapEnumOptions(confRes.status === "fulfilled" ? confRes.value.data : null, CONFIDENTIALITY_FALLBACK));
            setRiskOptions(mapEnumOptions(riskRes.status === "fulfilled" ? riskRes.value.data : null, RISK_FALLBACK));
        } catch (err) {
            setError("Failed to load form options.");
        } finally {
            setIsLoadingOptions(false);
        }
    };

    const handleChange = (e) => setFormData((prev) => ({ ...prev, [e.target.name]: e.target.value }));
    const handleNext = () => setCurrentStep((prev) => Math.min(prev + 1, 4));
    const handleBack = () => setCurrentStep((prev) => Math.max(prev - 1, 1));
    const handleClose = () => { if (!isSubmitting) onClose(); };

    const handleSubmit = async () => {
        setIsSubmitting(true);
        setError(null);
        try {
            const submitData = { ...formData };
            Object.keys(submitData).forEach(key => { if (submitData[key] === "") submitData[key] = null; });
            const result = await dispatch(createAsset(submitData));
            if (result.type === "assets/create/fulfilled") {
                await dispatch(fetchAssets());
                onClose();
            } else {
                let errorMessage = "Failed to create asset";
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

    const renderStepContent = () => {
        switch (currentStep) {
            case 1: return (
                <div className="form-grid">
                    <div className="form-group"><label>Asset Name <span className="required">*</span></label><input type="text" name="asset_name" value={formData.asset_name} onChange={handleChange} placeholder="e.g. Web Server 01" required disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>Hostname</label><input type="text" name="hostname" value={formData.hostname} onChange={handleChange} placeholder="e.g. web01.local" disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>Asset Type <span className="required">*</span></label><select name="asset_type_id" value={formData.asset_type_id} onChange={handleChange} required disabled={isLoadingOptions}><option value="">Select type</option>{assetTypes.map(t => <option key={t.id} value={t.id}>{t.type_name}</option>)}</select></div>
                    <div className="form-group"><label>Network Zone</label><select name="asset_role" value={formData.asset_role} onChange={handleChange} disabled={isLoadingOptions}><option value="">Select zone</option>{zones.map(z => <option key={z.id} value={z.zone_name}>{z.zone_name}</option>)}</select></div>
                    <div className="form-group"><label>Vendor</label><select name="manufacturer" value={formData.manufacturer} onChange={handleChange} disabled={isLoadingOptions}><option value="">Select vendor</option>{vendors.map(v => <option key={v.id} value={v.vendor_name}>{v.vendor_name}</option>)}</select></div>
                    <div className="form-group"><label>Model</label><input type="text" name="model" value={formData.model} onChange={handleChange} placeholder="e.g. R740" disabled={isLoadingOptions} /></div>
                </div>
            );
            case 2: return (
                <div className="form-grid">
                    <div className="form-group"><label>Serial Number</label><input type="text" name="serial_number" value={formData.serial_number} onChange={handleChange} placeholder="e.g. SN123" disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>Operating System</label><input type="text" name="os_name" value={formData.os_name} onChange={handleChange} placeholder="e.g. Ubuntu 22.04" disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>IP Address</label><input type="text" name="ip_address" value={formData.ip_address} onChange={handleChange} placeholder="e.g. 192.168.1.10" disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>MAC Address</label><input type="text" name="mac_address" value={formData.mac_address} onChange={handleChange} placeholder="e.g. 00:1A:2B:3C:4D:5E" disabled={isLoadingOptions} /></div>
                </div>
            );
            case 3: return (
                <div className="form-grid">
                    <div className="form-group"><label>Location</label><select name="location_id" value={formData.location_id} onChange={handleChange} disabled={isLoadingOptions}><option value="">Select location</option>{locations.map(l => <option key={l.id} value={l.id}>{l.site_name || l.location_name || `Location ${l.id}`}</option>)}</select></div>
                    <div className="form-group"><label>Owner</label><select name="owner_id" value={formData.owner_id} onChange={handleChange} disabled={isLoadingOptions}><option value="">Select owner</option>{owners.map(o => <option key={o.id} value={o.id}>{o.full_name}</option>)}</select></div>
                    <div className="form-group"><label>Status</label><select name="status" value={formData.status} onChange={handleChange} disabled={isLoadingOptions}>{statusOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}</select></div>
                </div>
            );
            case 4: return (
                <div className="form-grid">
                    <div className="form-group"><label>Confidentiality Level</label><select name="confidentiality_level" value={formData.confidentiality_level} onChange={handleChange} disabled={isLoadingOptions}><option value="">Select level</option>{confidentialityOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}</select></div>
                    <div className="form-group"><label>Risk Level</label><select name="risk_level" value={formData.risk_level} onChange={handleChange} disabled={isLoadingOptions}><option value="">Select level</option>{riskOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}</select></div>
                    <div className="form-group"><label>Last Audit Date</label><input type="date" name="last_audit_date" value={formData.last_audit_date} onChange={handleChange} disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>Last Patch Date</label><input type="date" name="last_patch_date" value={formData.last_patch_date} onChange={handleChange} disabled={isLoadingOptions} /></div>
                    <div className="form-group"><label>Asset Value (USD)</label><div className="input-with-icon"><span className="input-icon">$</span><input type="number" name="asset_value" value={formData.asset_value} onChange={handleChange} min="0" step="0.01" placeholder="0.00" disabled={isLoadingOptions} className="input-with-prefix" /></div></div>
                    <div className="form-group full-width"><label>Description</label><textarea name="description" value={formData.description} onChange={handleChange} rows="3" placeholder="Optional notes" disabled={isLoadingOptions} /></div>
                </div>
            );
            default: return null;
        }
    };

    if (!isOpen) return null;
    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div className="modal-content2 modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header"><h3>Add New Asset</h3><button className="modal-close" onClick={handleClose} disabled={isSubmitting}>✕</button></div>
                <div className="modal-body">
                    <div className="step-indicator">
                        <div className={`step ${currentStep >= 1 ? "active" : ""}`}>1. Basic Info</div>
                        <div className={`step ${currentStep >= 2 ? "active" : ""}`}>2. System</div>
                        <div className={`step ${currentStep >= 3 ? "active" : ""}`}>3. Location</div>
                        <div className={`step ${currentStep >= 4 ? "active" : ""}`}>4. Security</div>
                    </div>
                    {isLoadingOptions && <div className="loading-spinner">Loading...</div>}
                    {!isLoadingOptions && renderStepContent()}
                    {error && <div className="alert alert-error" style={{ marginTop: "12px" }}>{error}</div>}
                </div>
                <div className="modal-actions">
                    <button className="btn-cancel" onClick={handleClose} disabled={isSubmitting}>Cancel</button>
                    {currentStep > 1 && <button className="btn-secondary" onClick={handleBack} disabled={isSubmitting || isLoadingOptions}>Back</button>}
                    {currentStep < 4 && <button className="btn-submit" onClick={handleNext} disabled={isSubmitting || isLoadingOptions}>Next</button>}
                    {currentStep === 4 && <button className="btn-submit" onClick={handleSubmit} disabled={isSubmitting || isLoadingOptions}>{isSubmitting ? "Creating..." : "Create Asset"}</button>}
                </div>
            </div>
        </div>
    );
};