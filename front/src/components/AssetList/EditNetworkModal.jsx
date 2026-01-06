import { useState } from "react";
import { useDispatch } from "react-redux";
import { updateAsset, fetchAssets } from "../../store/assetSlice";

// Validation functions
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

export const EditNetworkModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [fieldErrors, setFieldErrors] = useState({});
    const [formData, setFormData] = useState({
        serial_number: asset.serial_number || "",
        os_name: asset.os_name || "",
        ip_address: asset.ip_address || "",
        mac_address: asset.mac_address || ""
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
        const ipCheck = validateIP(formData.ip_address);
        if (!ipCheck.valid) errors.ip_address = ipCheck.error;
        const macCheck = validateMAC(formData.mac_address);
        if (!macCheck.valid) errors.mac_address = macCheck.error;
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
                            if (result.payload.includes('serial_number')) {
                                errorMessage = `Serial Number "${formData.serial_number}" already exists. Please use a different serial number.`;
                                setFieldErrors({ serial_number: 'This serial number is already in use' });
                            } else if (result.payload.includes('ip_address')) {
                                errorMessage = `IP Address "${formData.ip_address}" already exists. Please use a different IP address.`;
                                setFieldErrors({ ip_address: 'This IP address is already in use' });
                            } else if (result.payload.includes('mac_address')) {
                                errorMessage = `MAC Address "${formData.mac_address}" already exists. Please use a different MAC address.`;
                                setFieldErrors({ mac_address: 'This MAC address is already in use' });
                            } else {
                                errorMessage = 'A duplicate value was detected. Please check your inputs.';
                            }
                        } else {
                            errorMessage = result.payload;
                        }
                    } else if (Array.isArray(result.payload)) {
                        errorMessage = result.payload.map(err => `${err.loc?.join('.') || 'field'}: ${err.msg}`).join(' | ');
                    } else if (result.payload.detail) {
                        const detail = result.payload.detail;
                        if (typeof detail === 'string' && (detail.includes('duplicate key') || detail.includes('UniqueViolation'))) {
                            if (detail.includes('serial_number')) {
                                errorMessage = `Serial Number "${formData.serial_number}" already exists. Please use a different serial number.`;
                                setFieldErrors({ serial_number: 'This serial number is already in use' });
                            } else if (detail.includes('ip_address')) {
                                errorMessage = `IP Address "${formData.ip_address}" already exists. Please use a different IP address.`;
                                setFieldErrors({ ip_address: 'This IP address is already in use' });
                            } else if (detail.includes('mac_address')) {
                                errorMessage = `MAC Address "${formData.mac_address}" already exists. Please use a different MAC address.`;
                                setFieldErrors({ mac_address: 'This MAC address is already in use' });
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
                                <input
                                    type="text"
                                    name="serial_number"
                                    value={formData.serial_number}
                                    onChange={handleChange}
                                    placeholder="e.g. SN123456789"
                                    disabled={isSubmitting}
                                    style={fieldErrors.serial_number ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                                />
                                {fieldErrors.serial_number && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.serial_number}</span>}
                            </div>
                            <div className="form-group">
                                <label>Operating System</label>
                                <input type="text" name="os_name" value={formData.os_name} onChange={handleChange} placeholder="e.g. Ubuntu 22.04" disabled={isSubmitting} />
                            </div>
                            <div className="form-group">
                                <label>IP Address</label>
                                <input
                                    type="text"
                                    name="ip_address"
                                    value={formData.ip_address}
                                    onChange={handleChange}
                                    placeholder="e.g. 192.168.1.10"
                                    disabled={isSubmitting}
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
                                    disabled={isSubmitting}
                                    style={fieldErrors.mac_address ? { borderColor: '#dc3545', backgroundColor: '#fff5f5' } : {}}
                                />
                                {fieldErrors.mac_address && <span style={{ display: 'block', color: '#dc3545', fontSize: '11px', marginTop: '3px' }}>{fieldErrors.mac_address}</span>}
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