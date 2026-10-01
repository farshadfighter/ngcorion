/**
 * NewScanModal - مطابق Figma
 * تغییرات: Dropdown به جای Radio, Scan Details باکس خاکستری، دکمه‌های درست
 */

import React, { useState } from 'react';
import '../../assets/autoDiscoveryStyle/NewScanModal.css';
import { t } from "../../i18n";

const NewScanModal = ({ onClose, onSubmit, isLoading }) => {
    const [formData, setFormData] = useState({
        job_name: '',
        target: '',
        scan_type: 'well_known_ports',
        ports: '',
        protocol: 'TCP',
        version_detection: false,
    });
    const [errors, setErrors] = useState({});

    // Validate IP/Range format
    const validateTarget = (value) => {
        value = value.trim();

        const isValidOctet = (octet) => {
            const num = parseInt(octet, 10);
            return octet === num.toString() && num >= 0 && num <= 255;
        };

        const isValidIP = (ip) => {
            const octets = ip.split('.');
            if (octets.length !== 4) return false;
            return octets.every(isValidOctet);
        };

        // Format 1: Single IP
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
            return isValidIP(value);
        }

        // Format 2: CIDR
        const cidrMatch = value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
        if (cidrMatch) {
            const [, ip, cidr] = cidrMatch;
            const cidrNum = parseInt(cidr, 10);
            return isValidIP(ip) && cidrNum >= 0 && cidrNum <= 32;
        };

        // Format 3: Range
        const rangeMatch = value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/);
        if (rangeMatch) {
            const [, baseIP, startOctet, endOctet] = rangeMatch;
            const fullStartIP = baseIP + startOctet;
            if (!isValidIP(fullStartIP)) return false;
            if (!isValidOctet(endOctet)) return false;
            const start = parseInt(startOctet, 10);
            const end = parseInt(endOctet, 10);
            return end >= start;
        }

        return false;
    };

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        const fieldValue = type === 'checkbox' ? checked : value;
        setFormData((prev) => ({ ...prev, [name]: fieldValue }));
        if (errors[name]) {
            setErrors((prev) => ({ ...prev, [name]: null }));
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        const newErrors = {};

        if (!formData.target.trim()) {
            newErrors.target = t("Target IP or range is required");
        } else if (!validateTarget(formData.target.trim())) {
            newErrors.target = t("Invalid format. Use: 192.168.1.1, 192.168.1.0/24, or 192.168.1.1-254");
        }

        if (formData.scan_type === 'custom_ports' && !formData.ports.trim()) {
            newErrors.ports = t("Custom ports are required");
        }

        if (Object.keys(newErrors).length > 0) {
            setErrors(newErrors);
            return;
        }

        const scanData = {
            target: formData.target.trim(),
            scan_type: formData.scan_type,
            protocol: formData.protocol,
            version_detection: formData.version_detection,
        };

        if (formData.job_name.trim()) {
            scanData.job_name = formData.job_name.trim();
        }

        if (formData.scan_type === 'custom_ports' && formData.ports.trim()) {
            scanData.ports = formData.ports.trim();
        }

        onSubmit(scanData);
    };

    // Get scan details based on scan type
    const getScanDetails = () => {
        const details = [];

        if (formData.scan_type === 'well_known_ports') {
            details.push(t("Ports: 1-1024 + common database/app ports"));
        } else if (formData.scan_type === 'all_ports') {
            details.push(t("Ports: 1-65535 (full scan, slowest)"));
        } else {
            details.push(`Ports: ${formData.ports || 'specify below'}`);
        }

        details.push(t("Protocol: {{protocol}} connect scan (-sT)", { protocol: formData.protocol }));
        details.push(t("Skip host discovery (-Pn), no DNS (-n)"));
        if (formData.version_detection) {
            details.push(t("Service version detection enabled (-sV) — slower"));
        }

        const flags = ['-sT', '-Pn', '-n'];
        if (formData.version_detection) flags.push('-sV');
        details.push(`Flags: ${flags.join(' ')}`);

        return details;
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="new-scan-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{t("New Network Scan")}</h2>
                    <button className="modal-close" onClick={onClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body">

                        {/* Grid دو ستونه برای فیلدهای اصلی */}
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px 24px' }}>

                            {/* Scan Name */}
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label htmlFor="job_name">{t("Scan Name")}</label>
                                <input
                                    type="text"
                                    id="job_name"
                                    name="job_name"
                                    value={formData.job_name}
                                    onChange={handleChange}
                                    className="form-input"
                                />
                            </div>

                            {/* Target */}
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label htmlFor="target">
                                   {t("Target IP or Range")}{" "} <span className="required">*</span>
                                </label>
                                <input
                                    type="text"
                                    id="target"
                                    name="target"
                                    value={formData.target}
                                    onChange={handleChange}
                                    className={`form-input ${errors.target ? 'error' : ''}`}
                                    placeholder="e.g. 192.168.1.0/24"
                                />
                                {errors.target && <p className="form-error">{errors.target}</p>}
                            </div>

                            {/* Scan Type */}
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label htmlFor="scan_type">{t("Scan Type")}</label>
                                <select
                                    id="scan_type"
                                    name="scan_type"
                                    value={formData.scan_type}
                                    onChange={handleChange}
                                    className="form-select"
                                >
                                    <option value="well_known_ports">{t("Well-Known Ports (1-1024)")}</option>
                                    <option value="all_ports">{t("All Ports (1-65535)")}</option>
                                    <option value="custom_ports">{t("Custom Ports")}</option>
                                </select>
                            </div>

                            {/* Protocol */}
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label htmlFor="protocol">{t("Protocol")}</label>
                                <select
                                    id="protocol"
                                    name="protocol"
                                    value={formData.protocol}
                                    onChange={handleChange}
                                    className="form-select"
                                >
                                    <option value="TCP">{t("TCP")}</option>
                                    <option value="UDP">{t("UDP")}</option>
                                    <option value="BOTH">{t("Both TCP & UDP")}</option>
                                </select>
                            </div>

                            {/* Custom Ports - full width, فقط وقتی custom انتخاب شده */}
                            {formData.scan_type === 'custom_ports' && (
                                <div className="form-group" style={{ marginBottom: 0, gridColumn: '1 / -1' }}>
                                    <label htmlFor="ports">
                                       {t("Custom Ports")}{" "} <span className="required">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        id="ports"
                                        name="ports"
                                        value={formData.ports}
                                        onChange={handleChange}
                                        className={`form-input ${errors.ports ? 'error' : ''}`}
                                        placeholder="e.g. 22,80,443,8080-8090"
                                    />
                                    {errors.ports && <p className="form-error">{errors.ports}</p>}
                                </div>
                            )}

                            {/* Version Detection - full width */}
                            <div className="form-group" style={{ marginBottom: 0, gridColumn: '1 / -1' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                    <input
                                        type="checkbox"
                                        name="version_detection"
                                        checked={formData.version_detection}
                                        onChange={handleChange}
                                        style={{ width: '18px', height: '18px', cursor: 'pointer', margin: 0, flexShrink: 0 }}
                                    />
                                    <label style={{ margin: 0, cursor: 'pointer', fontSize: '14px', fontWeight: '500' }}>
                                       {t("Enable Service Version Detection (-sV)")}
                                    </label>
                                </div>
                                <p className="form-hint" style={{ color: '#f59e0b', marginTop: '4px' }}>
                                   {t("⚠️ Version detection is slower but provides detailed service information")}
                                </p>
                            </div>

                        </div>

                        {/* Scan Details Box - full width */}
                        <div className="scan-details-box">
                            <h4>{t("Scan Details")}</h4>
                            <ul>
                                {getScanDetails().map((detail, index) => (
                                    <li key={index}>{detail}</li>
                                ))}
                            </ul>
                        </div>

                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn btn-cancel" onClick={onClose} disabled={isLoading}>
                           {t("Cancel")}
                        </button>
                        <button type="submit" className="btn btn-start-scan" disabled={isLoading}>
                            {isLoading ? t("Starting...") : t("Start Scan")}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );}

export default NewScanModal;
