/* ==========================================
   NGCORION - Scan Results Modal
   Shows discovered hosts from a completed scan
   ========================================== */

import React from 'react';
import './AutoDiscovery.css';

const ScanResultsModal = ({ scan, onClose }) => {
  if (!scan) return null;

  const hosts = scan.hosts || [];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-large" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h3>📊 Scan Results: {scan.job_name || scan.scan_id}</h3>
            <p className="modal-subtitle">
              Target: {scan.target} | Type: {scan.scan_type} | Found: {hosts.length} host(s)
            </p>
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="modal-body">
          {hosts.length === 0 ? (
            <div className="no-results">
              <p>⚠️ No hosts discovered in this scan</p>
              <p>The target may be offline or not responding</p>
            </div>
          ) : (
            <table className="results-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Hostname</th>
                  <th>MAC Address</th>
                  <th>OS Info</th>
                  <th>Open Ports</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((host, index) => (
                  <tr key={index}>
                    <td><strong>{host.ip_address}</strong></td>
                    <td>{host.hostname || '-'}</td>
                    <td><code>{host.mac_address || '-'}</code></td>
                    <td>
                      {host.os_name ? (
                        <>
                          {host.os_name}
                          {host.os_accuracy && <span className="accuracy"> ({host.os_accuracy}%)</span>}
                        </>
                      ) : '-'}
                    </td>
                    <td>
                      {host.ports && host.ports.length > 0 ? (
                        <div className="ports-list">
                          {host.ports.slice(0, 10).map((port, i) => (
                            <span key={i} className="port-tag" title={port.service || 'Unknown service'}>
                              {port.port}/{port.protocol}
                              {port.service && ` (${port.service})`}
                            </span>
                          ))}
                          {host.ports.length > 10 && (
                            <span className="port-more">+{host.ports.length - 10} more</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-muted">No open ports</span>
                      )}
                    </td>
                    <td>
                      <span className={`status-badge status-${host.state || 'unknown'}`}>
                        {host.state || 'unknown'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {scan.error_message && (
            <div className="error-box">
              <strong>⚠️ Error:</strong> {scan.error_message}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <div className="scan-summary">
            <span>Total Hosts: {scan.hosts_total || 0}</span>
            <span>Hosts Up: {scan.hosts_up || 0}</span>
            <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
            {scan.completed_at && (
              <span>Completed: {new Date(scan.completed_at).toLocaleString()}</span>
            )}
          </div>
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanResultsModal;
