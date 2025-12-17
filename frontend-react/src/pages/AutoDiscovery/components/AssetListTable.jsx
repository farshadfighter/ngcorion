/**
 * AssetListTable - Table of existing assets for discovery scans
 */

import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchAssets } from '../../../store/slices/assetsSlice';

const AssetListTable = ({ onScanAsset, isScanning }) => {
  const dispatch = useDispatch();
  const { assets, loading } = useSelector((state) => state.assets);

  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('');
  const [selectedIds, setSelectedIds] = useState([]);

  // Scan options modal state
  const [showScanOptions, setShowScanOptions] = useState(false);
  const [assetToScan, setAssetToScan] = useState(null);
  const [scanType, setScanType] = useState('well_known_ports');
  const [customPorts, setCustomPorts] = useState('');
  const [protocol, setProtocol] = useState('TCP');

  // Load assets on mount
  useEffect(() => {
    dispatch(fetchAssets());
  }, [dispatch]);

  // Filter assets based on search and type filter
  const filteredAssets = assets.filter((asset) => {
    const matchesSearch =
      !searchTerm ||
      asset.asset_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.ip_address?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.hostname?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesType = !filterType || asset.asset_type_id === parseInt(filterType);

    return matchesSearch && matchesType;
  });

  // Get unique asset types from assets
  const assetTypeOptions = [...new Set(assets.map((a) => a.asset_type))].filter(Boolean);

  // Toggle single selection
  const toggleSelect = (id) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  // Toggle all selection
  const toggleSelectAll = () => {
    if (selectedIds.length === filteredAssets.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredAssets.map((a) => a.id));
    }
  };

  // Open scan options modal
  const openScanOptions = (asset) => {
    if (!asset.ip_address) {
      alert('This asset does not have an IP address configured.');
      return;
    }
    setAssetToScan(asset);
    setScanType('well_known_ports');
    setCustomPorts('');
    setProtocol('TCP');
    setShowScanOptions(true);
  };

  // Handle scan submission
  const handleScanSubmit = () => {
    if (!assetToScan) return;

    if (scanType === 'custom_ports' && !customPorts.trim()) {
      alert('Please specify custom ports');
      return;
    }

    const scanData = {
      target: assetToScan.ip_address,
      job_name: `Scan: ${assetToScan.asset_name}`,
      scan_type: scanType,
      protocol: protocol,
    };

    if (scanType === 'custom_ports' && customPorts.trim()) {
      scanData.ports = customPorts.trim();
    }

    onScanAsset(scanData);
    setShowScanOptions(false);
    setAssetToScan(null);
  };

  // Close scan options modal
  const closeScanOptions = () => {
    setShowScanOptions(false);
    setAssetToScan(null);
  };

  // Handle scan selected assets
  const handleScanSelected = () => {
    const selectedAssets = filteredAssets.filter((a) => selectedIds.includes(a.id));
    const assetsWithIp = selectedAssets.filter((a) => a.ip_address);

    if (assetsWithIp.length === 0) {
      alert('None of the selected assets have IP addresses configured.');
      return;
    }

    if (assetsWithIp.length === 1) {
      openScanOptions(assetsWithIp[0]);
    } else {
      // For multiple IPs, show a note
      alert(`Selected ${assetsWithIp.length} assets with IPs. Please scan them individually or use the New Scan button with a CIDR range.`);
    }
  };

  if (loading) {
    return (
      <div className="table-loading">
        <div className="spinner-lg" />
        <p>Loading assets...</p>
      </div>
    );
  }

  return (
    <div className="asset-list-container">
      {/* Search and Filter Bar */}
      <div className="asset-toolbar">
        <div className="search-box">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
          <input
            type="text"
            placeholder="Search by name, IP, or hostname..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="filter-controls">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="filter-select"
          >
            <option value="">All Types</option>
            {assetTypeOptions.map((type) => (
              <option key={type?.id || type} value={type?.id}>
                {type?.type_name || type}
              </option>
            ))}
          </select>
          {selectedIds.length > 0 && (
            <button
              className="btn btn-sm btn-primary"
              onClick={handleScanSelected}
              disabled={isScanning}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
              Scan Selected ({selectedIds.length})
            </button>
          )}
        </div>
      </div>

      {/* Assets Table */}
      {filteredAssets.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <path d="M8 21h8M12 17v4" />
            </svg>
          </div>
          <h3>No Assets Found</h3>
          <p>
            {searchTerm || filterType
              ? 'No assets match your search criteria.'
              : 'No assets have been added yet. Add assets to run discovery scans on them.'}
          </p>
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th className="col-checkbox">
                  <input
                    type="checkbox"
                    checked={selectedIds.length === filteredAssets.length && filteredAssets.length > 0}
                    onChange={toggleSelectAll}
                  />
                </th>
                <th>Asset Name</th>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Type</th>
                <th>OS</th>
                <th>Status</th>
                <th className="col-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => (
                <tr key={asset.id}>
                  <td className="col-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(asset.id)}
                      onChange={() => toggleSelect(asset.id)}
                    />
                  </td>
                  <td>
                    <div className="asset-name-cell">
                      <span className="asset-name">{asset.asset_name}</span>
                      <span className="asset-id">#{asset.id}</span>
                    </div>
                  </td>
                  <td>
                    {asset.ip_address ? (
                      <span className="ip-address">{asset.ip_address}</span>
                    ) : (
                      <span className="text-muted">Not set</span>
                    )}
                  </td>
                  <td>{asset.hostname || <span className="text-muted">-</span>}</td>
                  <td>
                    {asset.asset_type ? (
                      <span className="type-badge">{asset.asset_type.type_name}</span>
                    ) : (
                      <span className="text-muted">-</span>
                    )}
                  </td>
                  <td>
                    {asset.os_name ? (
                      <span className="os-name">{asset.os_name}</span>
                    ) : (
                      <span className="text-muted">Unknown</span>
                    )}
                  </td>
                  <td>
                    <span className={`status-badge status-${asset.status?.toLowerCase() || 'active'}`}>
                      {asset.status || 'Active'}
                    </span>
                  </td>
                  <td className="col-actions">
                    <button
                      className="btn btn-sm btn-ghost"
                      onClick={() => openScanOptions(asset)}
                      disabled={!asset.ip_address || isScanning}
                      title={asset.ip_address ? 'Run discovery scan' : 'No IP address configured'}
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" />
                        <path d="M21 21l-4.35-4.35" />
                      </svg>
                      Scan
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Footer with count */}
      <div className="asset-list-footer">
        <span className="asset-count">
          Showing {filteredAssets.length} of {assets.length} assets
        </span>
      </div>

      {/* Scan Options Modal */}
      {showScanOptions && assetToScan && (
        <div className="modal-overlay" onClick={closeScanOptions}>
          <div className="modal modal-scan-options" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Scan Options</h2>
              <button className="modal-close" onClick={closeScanOptions}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="modal-body">
              {/* Asset Info */}
              <div className="scan-target-info">
                <div className="target-label">Target Asset</div>
                <div className="target-details">
                  <span className="target-name">{assetToScan.asset_name}</span>
                  <span className="target-ip">{assetToScan.ip_address}</span>
                </div>
              </div>

              {/* Scan Type */}
              <div className="form-group">
                <label>Scan Type</label>
                <div className="radio-group">
                  <label className={`radio-card ${scanType === 'well_known_ports' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="scan_type"
                      value="well_known_ports"
                      checked={scanType === 'well_known_ports'}
                      onChange={(e) => setScanType(e.target.value)}
                    />
                    <div className="radio-content">
                      <span className="radio-title">Well-Known Ports</span>
                      <span className="radio-desc">Ports 1-1024 (Fast)</span>
                    </div>
                    <span className="radio-badge recommended">Recommended</span>
                  </label>

                  <label className={`radio-card ${scanType === 'all_ports' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="scan_type"
                      value="all_ports"
                      checked={scanType === 'all_ports'}
                      onChange={(e) => setScanType(e.target.value)}
                    />
                    <div className="radio-content">
                      <span className="radio-title">All Ports</span>
                      <span className="radio-desc">Ports 1-65535 (Thorough but slow)</span>
                    </div>
                  </label>

                  <label className={`radio-card ${scanType === 'custom_ports' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="scan_type"
                      value="custom_ports"
                      checked={scanType === 'custom_ports'}
                      onChange={(e) => setScanType(e.target.value)}
                    />
                    <div className="radio-content">
                      <span className="radio-title">Custom Ports</span>
                      <span className="radio-desc">Specify ports below</span>
                    </div>
                  </label>
                </div>
              </div>

              {/* Custom Ports Input */}
              {scanType === 'custom_ports' && (
                <div className="form-group">
                  <label htmlFor="custom-ports">Custom Ports</label>
                  <input
                    type="text"
                    id="custom-ports"
                    value={customPorts}
                    onChange={(e) => setCustomPorts(e.target.value)}
                    placeholder="e.g., 80,443,8080 or 1-1000"
                    className="form-input"
                  />
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
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                  className="form-select"
                >
                  <option value="TCP">TCP (Recommended)</option>
                  <option value="UDP">UDP</option>
                  <option value="BOTH">Both TCP & UDP</option>
                </select>
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={closeScanOptions}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleScanSubmit}
                disabled={isScanning || (scanType === 'custom_ports' && !customPorts.trim())}
              >
                {isScanning ? (
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
          </div>
        </div>
      )}
    </div>
  );
};

export default AssetListTable;
