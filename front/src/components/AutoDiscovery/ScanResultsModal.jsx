/**
 * ScanResultsModal - Display detailed scan results
 * Updated: Changed to 3 cards (removed Hosts Up) and Close button to OK
 */

import React, { useState } from 'react';
import ManagePortsModal from './ManagePortsModal';
import "../../assets/autoDiscoveryStyle/ScanResultsModal.css"

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
        return new Date(dateStr).toLocaleString('en-US', {
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

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <div className="modal-title-group">
                        <h2>Scan Results</h2>
                        <span className="modal-subtitle">
              Scan: {scan.job_name || scan.scan_id} - {scan.target}
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
                            <span className="stat-value">{scan.hosts_discovered || hosts.length}</span>
                            <span className="stat-label">Discovered</span>
                        </div>
                        <div className="summary-stat">
                            <span className="stat-value">{getDuration()}</span>
                            <span className="stat-label">Duration</span>
                        </div>
                        <div className="summary-stat">
                            <span className={`stat-value status-text-${scan.status}`}>{scan.status}</span>
                            <span className="stat-label">Status</span>
                        </div>
                    </div>

                    {/* Error Message */}
                    {scan.error_message && (
                        <div className="alert alert-error">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="10" />
                                <path d="M12 8v4M12 16h.01" />
                            </svg>
                            <span>{scan.error_message}</span>
                        </div>
                    )}

                    {/* Hosts Table */}
                    {hosts.length === 0 ? (
                        <div className="empty-state small">
                            <p>No hosts were discovered in this scan.</p>
                            <p className="text-muted">The target may be offline or not responding to scans.</p>
                        </div>
                    ) : (
                        <div className="results-table-container">
                            <table className="data-table">
                                <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>OS Info</th>
                                    <th>Open Ports</th>
                                    <th>Actions</th>
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
                                                <span className="text-muted">Unknown</span>
                                            )}
                                        </td>
                                        <td>
                                            {host.ports && host.ports.length > 0 ? (
                                                <div className="ports-display">
                                                    {host.ports.slice(0, 6).map((port, i) => (
                                                        <span
                                                            key={i}
                                                            className="port-badge"
                                                            title={port.service || 'Unknown service'}
                                                        >
                                {port.port}/{port.protocol}
                                                            {port.service && ` (${port.service})`}
                              </span>
                                                    ))}
                                                    {host.ports.length > 6 && (
                                                        <span className="port-more">+{host.ports.length - 6}</span>
                                                    )}
                                                </div>
                                            ) : (
                                                <span className="text-muted">No open ports</span>
                                            )}
                                        </td>
                                        <td>
                                            <div className="action-buttons">
                                                <button
                                                    className="btn btn-sm btn-primary"
                                                    onClick={() => handleManagePorts(host)}
                                                    title="Manage ports for this host"
                                                >
                                                    Manage Asset
                                                </button>
                                                <button
                                                    className="btn btn-sm btn-icon btn-ghost btn-danger"
                                                    title="Delete host"
                                                >
                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                                                    </svg>
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
                        <h4>Scan Details</h4>
                        <div className="details-grid">
                            <div className="detail-item">
                                <span className="detail-label">Scan Name</span>
                                <span className="detail-value">{scan.job_name || scan.scan_id}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">Target</span>
                                <span className="detail-value">{scan.target}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">Scan Type</span>
                                <span className="detail-value">{scan.scan_type}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">Protocol</span>
                                <span className="detail-value">{scan.protocol || 'TCP'}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">Started</span>
                                <span className="detail-value">{formatDate(scan.started_at)}</span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">Completed</span>
                                <span className="detail-value">{formatDate(scan.completed_at)}</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="modal-footer">
                    <button className="btn btn-ok" onClick={onClose}>
                        OK
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
