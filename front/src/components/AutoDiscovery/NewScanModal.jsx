/**
 * NewScanModal - Modal for starting a new network scan
 */

import React, { useState } from 'react';

const NewScanModal = ({ onClose, onSubmit, isLoading }) => {
    const [formData, setFormData] = useState({
        job_name: '',
        target: '',
        scan_type: 'well_known_ports',
        ports: '',
        protocol: 'TCP',
    });
    const [errors, setErrors] = useState({});

    // 🔧 IMPROVED: Validate IP/Range format با چک کردن دقیق مقادیر
    const validateTarget = (value) => {
        value = value.trim();

        // Helper: بررسی یک octet (0-255)
        const isValidOctet = (octet) => {
            const num = parseInt(octet, 10);
            return octet === num.toString() && num >= 0 && num <= 255;
        };

        // Helper: بررسی یک IP آدرس کامل
        const isValidIP = (ip) => {
            const octets = ip.split('.');
            if (octets.length !== 4) return false;
            return octets.every(isValidOctet);
        };

        // Format 1: Single IP (192.168.1.1)
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
            return isValidIP(value);
        }

        // Format 2: CIDR notation (192.168.1.0/24)
        const cidrMatch = value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
        if (cidrMatch) {
            const [, ip, cidr] = cidrMatch;
            const cidrNum = parseInt(cidr, 10);
            return isValidIP(ip) && cidrNum >= 0 && cidrNum <= 32;
        }

        // Format 3: IP Range (192.168.1.1-254)
        const rangeMatch = value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/);
        if (rangeMatch) {
            const [, baseIP, startOctet, endOctet] = rangeMatch;
            const fullStartIP = baseIP + startOctet;

            // بررسی IP شروع
            if (!isValidIP(fullStartIP)) return false;

            // بررسی octet پایانی
            if (!isValidOctet(endOctet)) return false;

            // بررسی اینکه end >= start
            const start = parseInt(startOctet, 10);
            const end = parseInt(endOctet, 10);
            return end >= start;
        }

        return false;
    };

    // Handle input change
    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        // Clear error when user types
        if (errors[name]) {
            setErrors((prev) => ({ ...prev, [name]: null }));
        }
    };

    // Validate and submit
    const handleSubmit = (e) => {
        e.preventDefault();
        const newErrors = {};

        if (!formData.target.trim()) {
            newErrors.target = 'Target IP or range is required';
        } else if (!validateTarget(formData.target.trim())) {
            newErrors.target = 'Invalid format. Use: 192.168.1.1, 192.168.1.0/24, or 192.168.1.1-254';
        }

        if (formData.scan_type === 'custom_ports' && !formData.ports.trim()) {
            newErrors.ports = 'Custom ports are required for this scan type';
        }

        if (Object.keys(newErrors).length > 0) {
            setErrors(newErrors);
            return;
        }

        // Build scan data
        const scanData = {
            target: formData.target.trim(),
            scan_type: formData.scan_type,
            protocol: formData.protocol,
        };

        if (formData.job_name.trim()) {
            scanData.job_name = formData.job_name.trim();
        }

        if (formData.ports.trim()) {
            scanData.ports = formData.ports.trim();
        }

        onSubmit(scanData);
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal modal-scan" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>New Network Scan</h2>
                    <button className="modal-close" onClick={onClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        {/* Job Name */}
                        <div className="form-group">
                            <label htmlFor="job_name">Scan Name (Optional)</label>
                            <input
                                type="text"
                                id="job_name"
                                name="job_name"
                                value={formData.job_name}
                                onChange={handleChange}
                                placeholder="e.g., Office Network Scan"
                                className="form-input"
                            />
                            <p className="form-hint">A friendly name to identify this scan</p>
                        </div>

                        {/* Target */}
                        <div className="form-group">
                            <label htmlFor="target">
                                Target IP or Range <span className="required">*</span>
                            </label>
                            <input
                                type="text"
                                id="target"
                                name="target"
                                value={formData.target}
                                onChange={handleChange}
                                placeholder="e.g., 192.168.1.0/24"
                                className={`form-input ${errors.target ? 'error' : ''}`}
                            />
                            {errors.target && <p className="form-error">{errors.target}</p>}
                            <p className="form-hint">
                                Supported formats: Single IP (192.168.1.1), CIDR (192.168.1.0/24), Range (192.168.1.1-254)
                            </p>
                        </div>

                        {/* Scan Type */}
                        <div className="form-group">
                            <label htmlFor="scan_type">Scan Type</label>
                            <div className="radio-group">
                                <label className={`radio-card ${formData.scan_type === 'well_known_ports' ? 'selected' : ''}`}>
                                    <input
                                        type="radio"
                                        name="scan_type"
                                        value="well_known_ports"
                                        checked={formData.scan_type === 'well_known_ports'}
                                        onChange={handleChange}
                                    />
                                    <div className="radio-content">
                                        <span className="radio-title">Well-Known Ports</span>
                                        <span className="radio-desc">Ports 1-1024 (Recommended)</span>
                                    </div>
                                    <span className="radio-badge recommended">Recommended</span>
                                </label>

                                <label className={`radio-card ${formData.scan_type === 'all_ports' ? 'selected' : ''}`}>
                                    <input
                                        type="radio"
                                        name="scan_type"
                                        value="all_ports"
                                        checked={formData.scan_type === 'all_ports'}
                                        onChange={handleChange}
                                    />
                                    <div className="radio-content">
                                        <span className="radio-title">All Ports</span>
                                        <span className="radio-desc">Ports 1-65535 (Slowest)</span>
                                    </div>
                                </label>

                                <label className={`radio-card ${formData.scan_type === 'custom_ports' ? 'selected' : ''}`}>
                                    <input
                                        type="radio"
                                        name="scan_type"
                                        value="custom_ports"
                                        checked={formData.scan_type === 'custom_ports'}
                                        onChange={handleChange}
                                    />
                                    <div className="radio-content">
                                        <span className="radio-title">Custom Ports</span>
                                        <span className="radio-desc">Specify ports below</span>
                                    </div>
                                </label>
                            </div>
                        </div>

                        {/* Custom Ports */}
                        {formData.scan_type === 'custom_ports' && (
                            <div className="form-group">
                                <label htmlFor="ports">
                                    Custom Ports <span className="required">*</span>
                                </label>
                                <input
                                    type="text"
                                    id="ports"
                                    name="ports"
                                    value={formData.ports}
                                    onChange={handleChange}
                                    placeholder="e.g., 80,443,8080 or 1-1000"
                                    className={`form-input ${errors.ports ? 'error' : ''}`}
                                />
                                {errors.ports && <p className="form-error">{errors.ports}</p>}
                                <p className="form-hint">
                                    Examples: Single (80), List (80,443,8080), Range (1-1000)
                                </p>
                            </div>
                        )}

                        {/* Protocol */}
                        <div className="form-group">
                            <label htmlFor="protocol">Protocol</label>
                            <select
                                id="protocol"
                                name="protocol"
                                value={formData.protocol}
                                onChange={handleChange}
                                className="form-select"
                            >
                                <option value="TCP">TCP (Recommended)</option>
                                <option value="UDP">UDP</option>
                                <option value="BOTH">Both TCP & UDP</option>
                            </select>
                        </div>

                        {/* Scan Info Box */}
                        <div className="info-box">
                            <div className="info-box-header">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <circle cx="12" cy="12" r="10" />
                                    <path d="M12 16v-4M12 8h.01" />
                                </svg>
                                <span>Scan Details</span>
                            </div>
                            <ul className="info-list">
                                <li>Service version detection enabled (-sV)</li>
                                <li>TCP connect scan method (-sT)</li>
                                <li>Host discovery skipped (-Pn)</li>
                                <li>Results include open ports, OS info, and MAC address</li>
                            </ul>
                        </div>
                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn btn-secondary" onClick={onClose}>
                            Cancel
                        </button>
                        <button type="submit" className="btn btn-primary" disabled={isLoading}>
                            {isLoading ? (
                                <>
                                    <span className="spinner" />
                                    Starting...
                                </>
                            ) : (
                                <>
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="11" cy="11" r="8" />
                                        <path d="M21 21l-4.35-4.35" />
                                    </svg>
                                    Start Scan
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default NewScanModal;
