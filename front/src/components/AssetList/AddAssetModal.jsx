// AddAssetModal.jsx - WITH FRONTEND VALIDATION
import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { createAsset, fetchAssets } from "../../store/assetSlice";
import { getLicenseStatusThunk } from "../../store/licenseSlice";
import { fetchOSCatalog } from "../../store/requirementSlice";

import api from "../../config/api";
// Shared with EditSecurityModal (via useAssetFormOptions) so both forms offer
// exactly the risk tiers the scoring engine can score — see the note there.
import { dropUnscoredRiskLevels } from "./useAssetFormOptions";

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

// Validation functions matching Backend
const validateIP = (ip) => {
    if (!ip || ip.trim() === '') return { valid: true };
    const pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!pattern.test(ip)) {
        return { valid: false, error: 'Invalid IP address format (e.g., 192.168.1.1)' };
    }
    return { valid: true };
};

const validateMAC = (mac) => {
    if (!mac || mac.trim() === '') return { valid: true };
    const patterns = [
        /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
        /^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$/,
        /^[0-9A-Fa-f]{12}$/
    ];
    if (!patterns.some(pattern => pattern.test(mac))) {
        return { valid: false, error: 'Invalid MAC format. Use: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXX.XXXX.XXXX, or XXXXXXXXXXXX' };
    }
    return { valid: true };
};

const validateAssetName = (name) => {
    if (!name || name.trim().length < 2) {
        return { valid: false, error: 'Asset name must be at least 2 characters' };
    }
    return { valid: true };
};

const validateAssetValue = (value) => {
    if (value !== null && value !== '' && parseFloat(value) < 0) {
        return { valid: false, error: 'Asset value must be positive' };
    }
    return { valid: true };
};

export const AddAssetModal = ({ isOpen, onClose }) => {
    const dispatch = useDispatch();
    const osCatalog = useSelector((state) => state.requirements.osCatalog);

    const [currentStep, setCurrentStep] = useState(1);
    const [isLoadingOptions, setIsLoadingOptions] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [fieldErrors, setFieldErrors] = useState({});

    const [assetTypes, setAssetTypes] = useState([]);
    const [locations, setLocations] = useState([]);
    const [owners, setOwners] = useState([]);
    const [zones, setZones] = useState([]);
    const [vendors, setVendors] = useState([]);
    const [statusOptions, setStatusOptions] = useState(() => mapEnumOptions(null, STATUS_FALLBACK));
    const [confidentialityOptions, setConfidentialityOptions] = useState(() => mapEnumOptions(null, CONFIDENTIALITY_FALLBACK));
    const [riskOptions, setRiskOptions] = useState(() => dropUnscoredRiskLevels(mapEnumOptions(null, RISK_FALLBACK)));

    const [formData, setFormData] = useState({
        asset_name: "", hostname: "", asset_type_id: "", asset_role: "", manufacturer: "", model: "",
        serial_number: "", os_name: "", os_version: "", ip_address: "", mac_address: "", location_id: "",
        owner_id: "", status: "active", confidentiality_level: "", risk_level: "", last_audit_date: "",
        last_patch_date: "", asset_value: "", description: ""
    });

    const resetModal = () => {
        setCurrentStep(1);
        setError(null);
        setFieldErrors({});
        setIsSubmitting(false);
        setFormData({
            asset_name: "", hostname: "", asset_type_id: "", asset_role: "", manufacturer: "", model: "",
            serial_number: "", os_name: "", os_version: "", ip_address: "", mac_address: "", location_id: "",
            owner_id: "", status: "active", confidentiality_level: "", risk_level: "", last_audit_date: "",
            last_patch_date: "", asset_value: "", description: ""
        });
    };

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
            setRiskOptions(dropUnscoredRiskLevels(mapEnumOptions(riskRes.status === "fulfilled" ? riskRes.value.data : null, RISK_FALLBACK)));
        } catch (err) {
            setError("Failed to load form options.");
        } finally {
            setIsLoadingOptions(false);
        }
    };

    // Placed after loadDropdownOptions: `const` is not hoisted, so calling it
    // from an effect declared above hits the temporal dead zone.
    useEffect(() => {
        if (!isOpen) { resetModal(); return; }
        loadDropdownOptions();
        if (osCatalog.length === 0) {
            dispatch(fetchOSCatalog());
        }
    }, [isOpen]);


    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => {
            const next = { ...prev, [name]: value };
            // Reset os_version when os_name changes
            if (name === "os_name") next.os_version = "";
            return next;
        });
        if (fieldErrors[name]) {
            setFieldErrors(prev => {
                const newErrors = { ...prev };
                delete newErrors[name];
                return newErrors;
            });
        }
    };

    const validateCurrentStep = () => {
        const errors = {};

        if (currentStep === 1) {
            const nameCheck = validateAssetName(formData.asset_name);
            if (!nameCheck.valid) errors.asset_name = nameCheck.error;
            if (!formData.asset_type_id) errors.asset_type_id = "Asset Type is required";
        }

        if (currentStep === 2) {
            const ipCheck = validateIP(formData.ip_address);
            if (!ipCheck.valid) errors.ip_address = ipCheck.error;
            const macCheck = validateMAC(formData.mac_address);
            if (!macCheck.valid) errors.mac_address = macCheck.error;
        }

        if (currentStep === 4) {
            const valueCheck = validateAssetValue(formData.asset_value);
            if (!valueCheck.valid) errors.asset_value = valueCheck.error;
        }

        setFieldErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleNext = () => {
        if (validateCurrentStep()) {
            setCurrentStep((prev) => Math.min(prev + 1, 4));
        }
    };

    const handleBack = () => {
        setFieldErrors({});
        setCurrentStep((prev) => Math.max(prev - 1, 1));
    };

    const handleClose = () => { if (!isSubmitting) onClose(); };

    const handleSubmit = async () => {
        if (!validateCurrentStep()) return;

        setIsSubmitting(true);
        setError(null);
        try {
            const submitData = { ...formData };
            Object.keys(submitData).forEach(key => { if (submitData[key] === "") submitData[key] = null; });

            const result = await dispatch(createAsset(submitData));

            if (result.type === "assets/create/fulfilled") {
                await dispatch(fetchAssets());
                await dispatch(getLicenseStatusThunk());
                onClose();
            } else {
                let errorMessage = "Failed to create asset";

                if (result.payload) {
                    if (Array.isArray(result.payload)) {
                        errorMessage = result.payload.map(err => `${err.loc?.join('.') || 'field'}: ${err.msg}`).join(' | ');
                    } else if (typeof result.payload === 'string') {
                        if (result.payload.includes('duplicate key') || result.payload.includes('UniqueViolation')) {
                            if (result.payload.includes('serial_number')) {
                                errorMessage = `Serial Number "${formData.serial_number}" already exists. Please use a different serial number.`;
                                setFieldErrors({ serial_number: 'This serial number is already in use' });
                                setCurrentStep(2);
                            } else if (result.payload.includes('ip_address')) {
                                errorMessage = `IP Address "${formData.ip_address}" already exists. Please use a different IP address.`;
                                setFieldErrors({ ip_address: 'This IP address is already in use' });
                                setCurrentStep(2);
                            } else if (result.payload.includes('mac_address')) {
                                errorMessage = `MAC Address "${formData.mac_address}" already exists. Please use a different MAC address.`;
                                setFieldErrors({ mac_address: 'This MAC address is already in use' });
                                setCurrentStep(2);
                            } else {
                                errorMessage = 'A field with this value already exists. Please check your inputs.';
                            }
                        } else {
                            errorMessage = result.payload;
                        }
                    } else if (result.payload.detail) {
                        const detail = result.payload.detail;
                        if (typeof detail === 'string' && (detail.includes('duplicate key') || detail.includes('UniqueViolation'))) {
                            if (detail.includes('serial_number')) {
                                errorMessage = `Serial Number "${formData.serial_number}" already exists. Please use a different serial number.`;
                                setFieldErrors({ serial_number: 'This serial number is already in use' });
                                setCurrentStep(2);
                            } else if (detail.includes('ip_address')) {
                                errorMessage = `IP Address "${formData.ip_address}" already exists. Please use a different IP address.`;
                                setFieldErrors({ ip_address: 'This IP address is already in use' });
                                setCurrentStep(2);
                            } else if (detail.includes('mac_address')) {
                                errorMessage = `MAC Address "${formData.mac_address}" already exists. Please use a different MAC address.`;
                                setFieldErrors({ mac_address: 'This MAC address is already in use' });
                                setCurrentStep(2);
                            } else {
                                errorMessage = detail;
                            }
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
            let errorMessage = "An unexpected error occurred";
            if (err.message) {
                if (err.message.includes('duplicate key') || err.message.includes('UniqueViolation')) {
                    if (err.message.includes('serial_number')) {
                        errorMessage = `Serial Number "${formData.serial_number}" already exists. Please use a different serial number.`;
                        setFieldErrors({ serial_number: 'This serial number is already in use' });
                        setCurrentStep(2);
                    } else {
                        errorMessage = 'A duplicate value was detected. Please check your inputs.';
                    }
                } else {
                    errorMessage = err.message;
                }
            }
            setError(errorMessage);
        } finally {
            setIsSubmitting(false);
        }
    };

    const renderStepContent = () => {
        switch (currentStep) {
            case 1: return (
                <div className="form-grid">
                    <div className="form-group">
                        <label>Asset Name <span className="required">*</span></label>
                        <input
                            type="text"
                            name="asset_name"
                            value={formData.asset_name}
                            onChange={handleChange}
                            placeholder="e.g. Web Server 01"
                            required
                            disabled={isLoadingOptions}
                            style={fieldErrors.asset_name ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                        />
                        {fieldErrors.asset_name && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.asset_name}</span>}
                    </div>
                    <div className="form-group">
                        <label>Hostname</label>
                        <input type="text" name="hostname" value={formData.hostname} onChange={handleChange} placeholder="e.g. web01.local" disabled={isLoadingOptions} />
                    </div>
                    <div className="form-group">
                        <label>Asset Type <span className="required">*</span></label>
                        <select
                            name="asset_type_id"
                            value={formData.asset_type_id}
                            onChange={handleChange}
                            required
                            disabled={isLoadingOptions}
                            style={fieldErrors.asset_type_id ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                        >
                            <option value="">Select type</option>
                            {assetTypes.map(t => <option key={t.id} value={t.id}>{t.type_name}</option>)}
                        </select>
                        {fieldErrors.asset_type_id && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.asset_type_id}</span>}
                    </div>
                    <div className="form-group">
                        <label>Network Zone</label>
                        <select name="asset_role" value={formData.asset_role} onChange={handleChange} disabled={isLoadingOptions}>
                            <option value="">Select zone</option>
                            {zones.map(z => <option key={z.id} value={z.zone_name}>{z.zone_name}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Vendor</label>
                        <select name="manufacturer" value={formData.manufacturer} onChange={handleChange} disabled={isLoadingOptions}>
                            <option value="">Select vendor</option>
                            {vendors.map(v => <option key={v.id} value={v.vendor_name}>{v.vendor_name}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Model</label>
                        <input type="text" name="model" value={formData.model} onChange={handleChange} placeholder="e.g. R740" disabled={isLoadingOptions} />
                    </div>
                </div>
            );
            case 2: return (
                <div className="form-grid">
                    <div className="form-group">
                        <label>Serial Number</label>
                        <input type="text" name="serial_number" value={formData.serial_number} onChange={handleChange} placeholder="e.g. SN123" disabled={isLoadingOptions} />
                    </div>
                    <div className="form-group">
                        <label>Operating System</label>
                        <select
                            name="os_name"
                            value={formData.os_name}
                            onChange={handleChange}
                            disabled={isLoadingOptions}
                        >
                            <option value="">Select OS</option>
                            {[...new Map(osCatalog.map(os => [os.os_name, os])).values()].map(os => (
                                <option key={os.id} value={os.os_name}>{os.os_name}</option>
                            ))}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>OS Version</label>
                        <select
                            name="os_version"
                            value={formData.os_version}
                            onChange={handleChange}
                            disabled={isLoadingOptions || !formData.os_name}
                        >
                            <option value="">Select version</option>
                            {osCatalog
                                .filter(os => os.os_name === formData.os_name && os.os_version)
                                .map(os => (
                                    <option key={os.id} value={os.os_version}>{os.os_version}</option>
                                ))
                            }
                        </select>
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
                            style={fieldErrors.ip_address ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                        />
                        {fieldErrors.ip_address && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.ip_address}</span>}
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
                            style={fieldErrors.mac_address ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                        />
                        {fieldErrors.mac_address && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.mac_address}</span>}
                    </div>
                </div>
            );
            case 3: return (
                <div className="form-grid">
                    <div className="form-group">
                        <label>Location</label>
                        <select name="location_id" value={formData.location_id} onChange={handleChange} disabled={isLoadingOptions}>
                            <option value="">Select location</option>
                            {locations.map(l => <option key={l.id} value={l.id}>{l.site_name || l.location_name || `Location ${l.id}`}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Owner</label>
                        <select name="owner_id" value={formData.owner_id} onChange={handleChange} disabled={isLoadingOptions}>
                            <option value="">Select owner</option>
                            {owners.map(o => <option key={o.id} value={o.id}>{o.full_name}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Status</label>
                        <select name="status" value={formData.status} onChange={handleChange} disabled={isLoadingOptions}>
                            {statusOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                        </select>
                    </div>
                </div>
            );
            case 4: return (
                <div className="form-grid">
                    <div className="form-group">
                        <label>Confidentiality Level</label>
                        <select name="confidentiality_level" value={formData.confidentiality_level} onChange={handleChange} disabled={isLoadingOptions}>
                            <option value="">Select level</option>
                            {confidentialityOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Risk Level</label>
                        <select name="risk_level" value={formData.risk_level} onChange={handleChange} disabled={isLoadingOptions}>
                            <option value="">Select level</option>
                            {riskOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Last Audit Date</label>
                        <input type="date" name="last_audit_date" value={formData.last_audit_date} onChange={handleChange} disabled={isLoadingOptions} />
                    </div>
                    <div className="form-group">
                        <label>Last Patch Date</label>
                        <input type="date" name="last_patch_date" value={formData.last_patch_date} onChange={handleChange} disabled={isLoadingOptions} />
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
                                disabled={isLoadingOptions}
                                className="input-with-prefix"
                                style={fieldErrors.asset_value ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                            />
                        </div>
                        {fieldErrors.asset_value && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.asset_value}</span>}
                    </div>
                    <div className="form-group full-width">
                        <label>Description</label>
                        <textarea name="description" value={formData.description} onChange={handleChange} rows="3" placeholder="Optional notes" disabled={isLoadingOptions} />
                    </div>
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