/**
 * ScanHistoryTable - Table of past network scans
 */

import React from 'react';
import { isNmapMissing, NMAP_INSTALL_COMMAND } from './scanErrors.jsx';

const ScanHistoryTable = ({ scans, loading, onViewResults, onDelete }) => {
  // Format date
  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  // Get scan type label
  const getScanTypeLabel = (type) => {
    const labels = {
      all_ports: 'All Ports (1-65535)',
      well_known_ports: 'Well-Known (1-1024)',
      custom_ports: 'Custom Ports',
    };
    return labels[type] || type;
  };

  // Derive a human-readable label from status + optional error message
  const getStatusLabel = (scan) => {
    if (scan.status === 'failed') {
      if (isNmapMissing(scan.error)) return 'nmap Missing';
      const err = (scan.error || '').toLowerCase();
      if (err.includes('timed out') || err.includes('timeout')) return 'Timed Out';
      return 'Failed';
    }
    if (scan.status === 'cancelled') return 'Cancelled';
    if (scan.status === 'completed') return 'Completed';
    if (scan.status === 'running') return 'Running';
    if (scan.status === 'pending') return 'Pending';
    return scan.status;
  };

  // Tooltip text for the status badge. The raw nmap-missing string is
  // unactionable, so surface the install command instead.
  const getStatusTitle = (scan) => {
    if (isNmapMissing(scan.error)) {
      return `nmap روی سرور نصب نیست — ${NMAP_INSTALL_COMMAND}`;
    }
    return scan.error || undefined;
  };

  // Get status icon
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
            <path d="M22 4L12 14.01l-3-3" />
          </svg>
        );
      case 'running':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="spin">
            <path d="M21 12a9 9 0 11-6.219-8.56" />
          </svg>
        );
      case 'failed':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M12 8v4M12 16h.01" />
          </svg>
        );
      case 'cancelled':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M15 9l-6 6M9 9l6 6" />
          </svg>
        );
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className="table-loading">
        <div className="spinner-lg" />
        <p>Loading scan history...</p>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
        </div>
        <h3>No Scans Yet</h3>
        <p>Start your first network scan to discover assets on your network.</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Target</th>
            <th>Scan Type</th>
            <th>Status</th>
            <th>Hosts Found</th>
            <th>Started</th>
            <th className="col-actions">Actions</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.scan_id}>
              <td>
                <div className="scan-name">
                  <span className="name">{scan.job_name || `Scan ${scan.scan_id.slice(0, 8)}`}</span>
                  <code className="scan-id">{scan.scan_id.slice(0, 8)}</code>
                </div>
              </td>
              <td>
                <span className="target">{scan.target}</span>
              </td>
              <td>
                <span className="scan-type">{getScanTypeLabel(scan.scan_type)}</span>
              </td>
              <td>
                <span
                  className={`status-badge status-${scan.status}`}
                  title={getStatusTitle(scan)}
                >
                  {getStatusIcon(scan.status)}
                  {getStatusLabel(scan)}
                </span>
              </td>
              <td>
                {scan.status === 'completed' ? (
                  <span className="hosts-count">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                      <path d="M8 21h8M12 17v4" />
                    </svg>
                    {scan.hosts_up || 0}
                  </span>
                ) : (
                  <span className="text-muted">-</span>
                )}
              </td>
              <td>
                <span className="date">{formatDate(scan.started_at)}</span>
              </td>
              <td className="col-actions">
                <div className="action-buttons">
                  {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                    <button
                      className="btn btn-sm btn-ghost"
                      onClick={() => onViewResults(scan)}
                      title={scan.status === 'completed' ? 'View results' : 'View error details'}
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                      View
                    </button>
                  )}
                  <button
                    className="btn btn-sm btn-ghost btn-danger"
                    onClick={() => onDelete(scan.scan_id)}
                    title="Delete scan"
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
  );
};

export default ScanHistoryTable;
