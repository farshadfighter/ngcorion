/**
 * PendingHostsTable - Table of discovered hosts awaiting approval
 */

import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { rejectHost, bulkApproveHosts, fetchPendingHosts } from '../../store/discoverySlice.jsx';

const PendingHostsTable = ({ hosts, loading, onApprove, assetTypes }) => {
  const dispatch = useDispatch();
  const { loading: storeLoading } = useSelector((state) => state.discovery);

  const [selectedIds, setSelectedIds] = useState([]);
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [bulkAssetTypeId, setBulkAssetTypeId] = useState('');

  // Toggle single selection
  const toggleSelect = (id) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  // Toggle all selection
  const toggleSelectAll = () => {
    if (selectedIds.length === hosts.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(hosts.map((h) => h.id));
    }
  };

  // Handle reject
  const handleReject = async (host) => {
    if (window.confirm(`Reject host ${host.ip_address}? This will remove it from the pending list.`)) {
      await dispatch(rejectHost(host.id));
    }
  };

  // Handle bulk approve
  const handleBulkApprove = async () => {
    if (!bulkAssetTypeId) {
      alert('Please select an asset type');
      return;
    }

    const result = await dispatch(bulkApproveHosts({
      hostIds: selectedIds,
      defaultAssetTypeId: parseInt(bulkAssetTypeId),
    }));

    if (result.type.includes('fulfilled')) {
      setSelectedIds([]);
      setShowBulkModal(false);
      setBulkAssetTypeId('');
      dispatch(fetchPendingHosts());
    }
  };

  // Format ports for display
  const formatPorts = (ports) => {
    if (!ports || ports.length === 0) return '-';
    const displayed = ports.slice(0, 4);
    const remaining = ports.length - 4;
    return (
      <div className="ports-display">
        {displayed.map((port, i) => (
          <span key={i} className="port-badge">
            {port.port}/{port.protocol}
          </span>
        ))}
        {remaining > 0 && <span className="port-more">+{remaining}</span>}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="table-loading">
        <div className="spinner-lg" />
        <p>Loading pending hosts...</p>
      </div>
    );
  }

  if (hosts.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
            <path d="M22 4L12 14.01l-3-3" />
          </svg>
        </div>
        <h3>No Pending Hosts</h3>
        <p>All discovered hosts have been processed. Start a new scan to discover more assets.</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      {/* Bulk Actions */}
      {selectedIds.length > 0 && (
        <div className="bulk-actions-bar">
          <span className="bulk-count">{selectedIds.length} host(s) selected</span>
          <div className="bulk-buttons">
            <button
              className="btn btn-sm btn-primary"
              onClick={() => setShowBulkModal(true)}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                <path d="M22 4L12 14.01l-3-3" />
              </svg>
              Bulk Approve
            </button>
            <button
              className="btn btn-sm btn-ghost"
              onClick={() => setSelectedIds([])}
            >
              Clear Selection
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <table className="data-table">
        <thead>
          <tr>
            <th className="col-checkbox">
              <input
                type="checkbox"
                checked={selectedIds.length === hosts.length && hosts.length > 0}
                onChange={toggleSelectAll}
              />
            </th>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>MAC Address</th>
            <th>OS Info</th>
            <th>Open Ports</th>
            <th>Status</th>
            <th className="col-actions">Actions</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <tr key={host.id} className={host.highlight ? 'row-highlight' : ''}>
              <td className="col-checkbox">
                <input
                  type="checkbox"
                  checked={selectedIds.includes(host.id)}
                  onChange={() => toggleSelect(host.id)}
                />
              </td>
              <td>
                <span className="ip-address">{host.ip_address}</span>
              </td>
              <td>{host.hostname || <span className="text-muted">-</span>}</td>
              <td>
                {host.mac_address ? (
                  <code className="mac-address">{host.mac_address}</code>
                ) : (
                  <span className="text-muted">-</span>
                )}
              </td>
              <td>
                {host.os_info ? (
                  <div className="os-info">
                    <span>{host.os_info}</span>
                    {host.os_accuracy && (
                      <span className="os-accuracy">{host.os_accuracy}%</span>
                    )}
                  </div>
                ) : (
                  <span className="text-muted">Unknown</span>
                )}
              </td>
              <td>{formatPorts(host.open_ports)}</td>
              <td>
                <span className={`status-badge status-${host.status}`}>
                  {host.status}
                </span>
              </td>
              <td className="col-actions">
                <div className="action-buttons">
                  <button
                    className="btn btn-sm btn-success"
                    onClick={() => onApprove(host)}
                    title="Approve host"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 6L9 17l-5-5" />
                    </svg>
                    Approve
                  </button>
                  <button
                    className="btn btn-sm btn-ghost btn-danger"
                    onClick={() => handleReject(host)}
                    title="Reject host"
                    disabled={storeLoading.approve}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Bulk Approve Modal */}
      {showBulkModal && (
        <div className="modal-overlay" onClick={() => setShowBulkModal(false)}>
          <div className="modal modal-sm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Bulk Approve Hosts</h3>
              <button className="modal-close" onClick={() => setShowBulkModal(false)}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="modal-body">
              <p className="modal-text">
                You are about to create assets for <strong>{selectedIds.length}</strong> discovered hosts.
                Please select a default asset type for all new assets.
              </p>
              <div className="form-group">
                <label htmlFor="bulk-asset-type">Asset Type</label>
                <select
                  id="bulk-asset-type"
                  value={bulkAssetTypeId}
                  onChange={(e) => setBulkAssetTypeId(e.target.value)}
                  className="form-select"
                >
                  <option value="">Select asset type...</option>
                  {assetTypes?.map((type) => (
                    <option key={type.id} value={type.id}>
                      {type.type_name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setShowBulkModal(false)}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleBulkApprove}
                disabled={!bulkAssetTypeId || storeLoading.approve}
              >
                {storeLoading.approve ? (
                  <>
                    <span className="spinner" />
                    Processing...
                  </>
                ) : (
                  `Approve ${selectedIds.length} Hosts`
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PendingHostsTable;
