/**
 * ScanResultsModal - Display detailed scan results
 * Updated: Changed to 3 cards (removed Hosts Up) and Close button to OK
 */

import React, { useState } from 'react';
import ManagePortsModal from './ManagePortsModal';
import ScanErrorAlert from './scanErrors.jsx';
import "../../assets/autoDiscoveryStyle/ScanResultsModal.css"
import { t, uiLocale, n } from "../../i18n";
import { tv } from "../../i18n/backendText";

const ScanResultsModal = ({ scan, onClose }) => {
    const [selectedHost, setSelectedHost] = useState(null);
    const [showManagePorts, setShowManagePorts] = useState(false);

    if (!scan) return null;

    const hosts = scan.hosts || [];

    // Handle opening Manage Ports modal
    const handleManagePorts = (host) => {
        setSelectedHost(host);
        setShowManagePorts(true);
    };

    // Handle successful port management
    const handleManageSuccess = (result) => {
        console.log('Port management successful:', result);
        // Optionally refresh scan results or show success message
    };

    // Format date
    const formatDate = (dateStr) => {
        if (!dateStr) return '-';
        return new Date(dateStr).toLocaleString(uiLocale(),  {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    };

    // Calculate duration
    const getDuration = () => {
        if (!scan.started_at || !scan.completed_at) return '-';
        const start = new Date(scan.started_at);
        const end = new Date(scan.completed_at);
        const seconds = Math.floor((end - start) / 1000);
        if (seconds < 60) return `${seconds}s`;
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}m ${remainingSeconds}s`;
    };

    // Render ports with state color coding
    const renderPorts = (ports) => {
        const allPorts = ports || [];
        if (allPorts.length === 0) {
            return <span className="text-muted">{t("No ports found")}</span>;
        }

        const openPorts = allPorts.filter(p => p.state === 'open' || !p.state);
        const closedPorts = allPorts.filter(p => p.state === 'closed');
        const filteredPorts = allPorts.filter(p => p.state === 'filtered');

        const shown = [
            ...openPorts.slice(0, 5),
            ...closedPorts.slice(0, 3),
            ...filteredPorts.slice(0, 2),
        ];
        const remaining = allPorts.length - shown.length;

        return (
            <div className="ports-display">
                {openPorts.slice(0, 5).map((port, i) => (
                    <span
                        key={i}
                        className="port-badge port-state-open"
                        title={`open${port.service ? ` - ${port.service}` : ''}`}
                    >
                        {port.port}/{port.protocol}
                        {port.service && ` (${port.service})`}
                    </span>
                ))}
                {closedPorts.slice(0, 3).map((port, i) => (
                    <span
                        key={`c${i}`}
                        className="port-badge port-state-closed"
                        title="closed"
                    >
                        {port.port}/{port.protocol}
                    </span>
                ))}
                {filteredPorts.slice(0, 2).map((port, i) => (
                    <span
                        key={`f${i}`}
                        className="port-badge port-state-filtered"
                        title="filtered"
                    >
                        {port.port}/{port.protocol}
                    </span>
                ))}
                {remaining > 0 && (
                    <span className="port-more">{t("+{{remaining}} more", { remaining })}</span>
                )}
                {closedPorts.length > 0 && (
                    <span className="port-state-label closed">{t("{{length}} closed", { length: closedPorts.length })}</span>
                )}
            </div>
        );
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <div className="modal-title-group">
                        <h2>{t("Scan Results")}</h2>
                        <span className="modal-subtitle">
              {t("Scan:")}{" "} {scan.job_name || scan.scan_id} - {scan.target}
            </span>
                    </div>
                    <button className="modal-close" onClick={onClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="modal-body">
                    {/* Summary Stats - 3 cards only */}
                    <div className="results-summary">
                        <div className="summary-stat">
                            <span className="stat-value">{n(scan.hosts_discovered || hosts.length)}</span>
                            <span className="stat-label">{t("Discovered")}</span>
                        </div>
                        <div className="summary-stat">
                            <span className="stat-value">{getDuration()}</span>
                            <span className="stat-label">{t("Duration")}</span>
                        </div>
                        <div className="summary-stat">
                            <span className={`stat-value status-text-${scan.status}`}>{scan.status}</span>
                            <span className="stat-label">{t("Status")}</span>
                        </div>
                    </div>

                    {/* Error Message — field is 'error' from list API, 'error_message' from detail API */}
                    <ScanErrorAlert error={scan.error_message || scan.error} />

                    {/* Hosts Table */}
                    {hosts.length === 0 ? (
                        <div className="empty-state small">
                            <p>{t("No hosts were discovered in this scan.")}</p>
                            <p className="text-muted">{t("The target may be offline or not responding to scans.")}</p>
                        </div>
                    ) : (
                        <div className="results-table-container">
                            <div className="port-legend">
                                <span className="port-badge port-state-open" style={{pointerEvents:'none'}}>{t("open")}</span>
                                <span className="port-badge port-state-closed" style={{pointerEvents:'none'}}>{t("closed")}</span>
                                <span className="port-badge port-state-filtered" style={{pointerEvents:'none'}}>{t("filtered")}</span>
                            </div>
                            <table className="data-table">
                                <thead>
                                <tr>
                                    <th>{t("IP Address")}</th>
                                    <th>{t("OS Info")}</th>
                                    <th>{t("Ports")}</th>
                                    <th>{t("Actions")}</th>
                                </tr>
                                </thead>
                                <tbody>
                                {hosts.map((host, index) => (
                                    <tr key={index}>
                                        <td>
                                            <span className="ip-address">{host.ip_address}</span>
                                        </td>
                                        <td>
                                            {host.os_name || host.os_info ? (
                                                <div className="os-info">
                                                    <span>{host.os_name || host.os_info}</span>
                                                    {host.os_accuracy && (
                                                        <span className="os-accuracy">{host.os_accuracy}%</span>
                                                    )}
                                                </div>
                                            ) : (
                                                <span className="text-muted">{t("Unknown")}</span>
                                            )}
                                        </td>
                                        <td>{renderPorts(host.ports)}</td>
                                        <td>
                                            <div className="action-buttons">
                                                <button
                                                    className="btn btn-sm btn-primary"
                                                    onClick={() => handleManagePorts(host)}
                                                    title={t("Manage ports for this host")}
                                                >
                                                    {t("Manage Asset")}
                                                </button>

                                            </div>
                                        </td>
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* Scan Details */}
                    <div className="scan-details">
                        <h4>{t("Scan Details")}</h4>
                        <div className="details-grid">
                            <div className="detail-item">
                                <span className="detail-label">{t("Scan Name")}</span>
                                <span className="detail-value">{scan.job_name || scan.scan_id}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">{t("Target")}</span>
                                <span className="detail-value">{scan.target}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">{t("Scan Type")}</span>
                                <span className="detail-value">{tv(scan.scan_type)}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">{t("Protocol")}</span>
                                <span className="detail-value">{scan.protocol || t("TCP")}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">{t("Started")}</span>
                                <span className="detail-value">{formatDate(scan.started_at)}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">{t("Completed")}</span>
                                <span className="detail-value">{formatDate(scan.completed_at)}</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="modal-footer">
                    <button className="btn btn-ok" onClick={onClose}>
                        {t("OK")}
                    </button>
                </div>
            </div>

            {/* Manage Ports Modal */}
            {showManagePorts && selectedHost && (
                <ManagePortsModal
                    host={selectedHost}
                    onClose={() => {
                        setShowManagePorts(false);
                        setSelectedHost(null);
                    }}
                    onSuccess={handleManageSuccess}
                />
            )}
        </div>
    );
};

export default ScanResultsModal;
