/* ==========================================
   NGCORION - Auto Discovery Page
   Main page for network scanning
   ========================================== */

import React, { useState, useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  startScan,
  checkScanStatus,
  fetchAllScans,
  matchIpToAsset,
  applyDiscovery,
  clearCurrentScan,
  clearError,
  stopScanning,
  clearAllScans,
  addLogEntry,
  fetchPendingHosts,
  checkMatches,
  approveHost,
  rejectHost,
  bulkApproveHosts,
} from '../../store/slices/discoverySlice';
import { fetchAssetTypes } from '../../store/slices/assetsSlice';
import DiscoveryResultModal from './DiscoveryResultModal';
import ActivityLog from './ActivityLog';
import './AutoDiscovery.css';

const AutoDiscovery = () => {
  const dispatch = useDispatch();
  
  // Redux state
  const {
    currentScan,
    scanHistory,
    isScanning,
    isLoadingScans,
    discoveredHosts,
    error,
    pendingHosts,
    matchResults,
    isLoadingPending,
  } = useSelector((state) => state.discovery);

  const { assetTypes } = useSelector((state) => state.assets);

  // Local state
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [ports, setPorts] = useState('');
  const [protocol, setProtocol] = useState('TCP');
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedHost, setSelectedHost] = useState(null);
  const [showResultModal, setShowResultModal] = useState(false);
  const [selectedPendingIds, setSelectedPendingIds] = useState([]);
  const [showMatchModal, setShowMatchModal] = useState(false);
  
  // Polling interval ref
  const pollIntervalRef = useRef(null);
  
  // Load scan history and asset types on mount
  useEffect(() => {
    dispatch(fetchAllScans());
    dispatch(fetchAssetTypes());
    dispatch(fetchPendingHosts());

    return () => {
      // Cleanup polling on unmount
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [dispatch]);
  
  // Poll for scan status when scanning
  useEffect(() => {
    if (currentScan && currentScan.status === 'running') {
      pollIntervalRef.current = setInterval(() => {
        dispatch(checkScanStatus(currentScan.scan_id));
      }, 3000); // Poll every 3 seconds
    } else {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    }
    
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [currentScan, dispatch]);
  
  // Validate IP/Range format
  const validateTarget = (value) => {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const rangePattern = /^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$/;
    return ipPattern.test(value) || rangePattern.test(value);
  };
  
  // Start scan handler
  const handleStartScan = () => {
    if (!target.trim()) {
      alert('Please enter an IP address or range');
      return;
    }

    if (!validateTarget(target.trim())) {
      alert('Invalid IP format. Use: 192.168.1.1, 192.168.1.0/24, or 192.168.1.1-254');
      return;
    }

    const scanData = {
      target: target.trim(),
      scan_type: scanType,
      protocol: protocol
    };

    // Add ports if specified
    if (ports.trim()) {
      scanData.ports = ports.trim();
    }

    dispatch(startScan(scanData));
    setShowScanModal(false);

    // Refresh pending hosts after scan completes
    setTimeout(() => {
      dispatch(fetchPendingHosts());
    }, 5000);
  };
  
  // Handle host click - check if matches existing asset
  const handleHostClick = async (host) => {
    setSelectedHost(host);
    await dispatch(matchIpToAsset(host.ip_address));
    setShowResultModal(true);
  };

  // Check for matching assets before approval
  const handleCheckMatches = async (hostId) => {
    await dispatch(checkMatches(hostId));
    setShowMatchModal(true);
  };

  // Approve a discovered host
  const handleApprove = async (hostId, action = 'create_new', assetId = null) => {
    const result = await dispatch(approveHost({ hostId, action, assetId }));

    if (result.type === 'discovery/approveHost/fulfilled') {
      alert(`✅ ${result.payload.message}`);
      dispatch(fetchPendingHosts()); // Refresh list
      setShowMatchModal(false);
    } else {
      alert(`❌ Failed: ${result.payload || 'Unknown error'}`);
    }
  };

  // Reject a discovered host
  const handleReject = async (hostId) => {
    if (!window.confirm('Are you sure you want to reject this discovered host?')) {
      return;
    }

    const result = await dispatch(rejectHost(hostId));

    if (result.type === 'discovery/rejectHost/fulfilled') {
      alert('✅ Host rejected');
      dispatch(fetchPendingHosts());
    } else {
      alert('❌ Failed to reject host');
    }
  };

  // Bulk approve selected hosts
  const handleBulkApprove = async () => {
    if (selectedPendingIds.length === 0) {
      alert('Please select hosts to approve');
      return;
    }

    const defaultTypeId = prompt('Enter default asset type ID:');
    if (!defaultTypeId) return;

    const result = await dispatch(bulkApproveHosts({
      hostIds: selectedPendingIds,
      defaultAssetTypeId: parseInt(defaultTypeId)
    }));

    if (result.type === 'discovery/bulkApprove/fulfilled') {
      alert(`✅ Approved ${result.payload.approved} hosts`);
      setSelectedPendingIds([]);
      dispatch(fetchPendingHosts());
    } else {
      alert('❌ Bulk approval failed');
    }
  };

  // Toggle selection of pending host
  const toggleSelection = (hostId) => {
    setSelectedPendingIds(prev =>
      prev.includes(hostId)
        ? prev.filter(id => id !== hostId)
        : [...prev, hostId]
    );
  };

  // Select all pending hosts
  const selectAll = () => {
    if (selectedPendingIds.length === pendingHosts.length) {
      setSelectedPendingIds([]);
    } else {
      setSelectedPendingIds(pendingHosts.map(h => h.id));
    }
  };
  
  // Format date
  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('fa-IR');
  };
  
  // Get status badge class
  const getStatusClass = (status) => {
    switch (status) {
      case 'running': return 'status-running';
      case 'completed': return 'status-completed';
      case 'failed': return 'status-failed';
      default: return '';
    }
  };
  
  // Get scan type label
  const getScanTypeLabel = (type) => {
    switch (type) {
      case 'basic': return 'Basic (~30s)';
      case 'detailed': return 'Detailed (~2-3min)';
      case 'full': return 'Full (~10+min)';
      default: return type;
    }
  };

  return (
    <div className="discovery-page">
      {/* Header */}
      <div className="discovery-header">
        <h1>🔍 Asset Auto Discovery</h1>
        <p>Scan your network to discover assets automatically</p>
      </div>
      
      {/* Error Display */}
      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={() => dispatch(clearError())}>×</button>
        </div>
      )}
      
      {/* Action Bar */}
      <div className="discovery-actions">
        <button 
          className="btn btn-primary"
          onClick={() => setShowScanModal(true)}
          disabled={isScanning}
        >
          {isScanning ? '⏳ Scanning...' : '➕ New Scan'}
        </button>
        
        {isScanning && (
          <button 
            className="btn btn-danger"
            onClick={() => {
              dispatch(stopScanning());
              if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
                pollIntervalRef.current = null;
              }
            }}
          >
            ⏹️ Stop Scan
          </button>
        )}
        
        <button 
          className="btn btn-secondary"
          onClick={() => dispatch(fetchAllScans())}
          disabled={isLoadingScans}
        >
          🔄 Refresh
        </button>
        
        {scanHistory.length > 0 && (
          <button 
            className="btn btn-danger-outline"
            onClick={() => {
              if (window.confirm('Are you sure you want to clear all scan history?')) {
                dispatch(clearAllScans());
              }
            }}
            disabled={isLoadingScans}
          >
            🗑️ Clear History
          </button>
        )}
      </div>
      
      {/* Current Scan Progress */}
      {currentScan && currentScan.status === 'running' && (
        <div className="scan-progress">
          <div className="progress-header">
            <span>🔍 Scanning: {currentScan.target}</span>
            <span className="scan-type">{getScanTypeLabel(currentScan.scan_type)}</span>
          </div>
          <div className="progress-bar">
            <div className="progress-bar-inner scanning"></div>
          </div>
          <p className="progress-text">
            Please wait... Scan started at {formatDate(currentScan.started_at)}
          </p>
        </div>
      )}
      
      {/* Pending Hosts Awaiting Approval */}
      {pendingHosts.length > 0 && (
        <div className="pending-hosts-section">
          <div className="section-header">
            <h2>⚠️ Discovered Hosts Awaiting Approval ({pendingHosts.length})</h2>
            <div className="bulk-actions">
              <button
                className="btn btn-small"
                onClick={selectAll}
              >
                {selectedPendingIds.length === pendingHosts.length ? 'Deselect All' : 'Select All'}
              </button>
              {selectedPendingIds.length > 0 && (
                <button
                  className="btn btn-small btn-primary"
                  onClick={handleBulkApprove}
                >
                  Approve Selected ({selectedPendingIds.length})
                </button>
              )}
            </div>
          </div>

          <table className="pending-hosts-table">
            <thead>
              <tr>
                <th><input type="checkbox" onChange={selectAll} checked={selectedPendingIds.length === pendingHosts.length} /></th>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC Address</th>
                <th>OS Info</th>
                <th>Open Ports</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pendingHosts.map((host) => (
                <tr key={host.id} className={host.highlight ? 'pending-host-row' : ''}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedPendingIds.includes(host.id)}
                      onChange={() => toggleSelection(host.id)}
                    />
                  </td>
                  <td><strong>{host.ip_address}</strong></td>
                  <td>{host.hostname || '-'}</td>
                  <td>{host.mac_address || '-'}</td>
                  <td>
                    {host.os_info ? (
                      <>
                        {host.os_info}
                        {host.os_accuracy && <span className="accuracy"> ({host.os_accuracy}%)</span>}
                      </>
                    ) : '-'}
                  </td>
                  <td>
                    {host.open_ports && host.open_ports.length > 0 ? (
                      <div className="ports-inline">
                        {host.open_ports.slice(0, 5).map((port, i) => (
                          <span key={i} className="port-tag">
                            {port.port}/{port.protocol}
                          </span>
                        ))}
                        {host.open_ports.length > 5 && (
                          <span className="port-more">+{host.open_ports.length - 5}</span>
                        )}
                      </div>
                    ) : '-'}
                  </td>
                  <td>
                    <span className={`status-badge status-${host.status}`}>
                      {host.status}
                    </span>
                  </td>
                  <td className="actions-cell">
                    <button
                      className="btn btn-small btn-success"
                      onClick={() => handleCheckMatches(host.id)}
                      title="Check for matches and approve"
                    >
                      ✓ Check & Approve
                    </button>
                    <button
                      className="btn btn-small btn-danger"
                      onClick={() => handleReject(host.id)}
                      title="Reject this host"
                    >
                      ✗
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      
      {/* Scan History */}
      <div className="scan-history">
        <h2>📋 Scan History</h2>
        {isLoadingScans ? (
          <p className="loading">Loading...</p>
        ) : scanHistory.length === 0 ? (
          <p className="empty">No scans yet. Start your first scan!</p>
        ) : (
          <table className="history-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Hosts Found</th>
                <th>Started</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.map((scan) => (
                <tr key={scan.scan_id}>
                  <td><code>{scan.scan_id}</code></td>
                  <td>{scan.target}</td>
                  <td>{scan.scan_type}</td>
                  <td>
                    <span className={`status-badge ${getStatusClass(scan.status)}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{scan.hosts_up || 0} / {scan.hosts_total || 0}</td>
                  <td>{formatDate(scan.started_at)}</td>
                  <td>
                    <button 
                      className="btn btn-small"
                      onClick={() => dispatch(checkScanStatus(scan.scan_id))}
                    >
                      View Results
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      
      {/* Activity Log */}
      <ActivityLog />
      
      {/* New Scan Modal */}
      {showScanModal && (
        <div className="modal-overlay" onClick={() => setShowScanModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>🔍 New Network Scan</h3>
              <button className="close-btn" onClick={() => setShowScanModal(false)}>×</button>
            </div>
            
            <div className="modal-body">
              <div className="form-group">
                <label>Target IP or Range *</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g., 192.168.1.1 or 192.168.1.0/24"
                />
                <small>
                  Formats: Single IP (192.168.1.1), CIDR (192.168.1.0/24), Range (192.168.1.1-254)
                </small>
              </div>

              <div className="form-group">
                <label>Scan Type</label>
                <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
                  <option value="basic">Basic - Fast (~30 seconds)</option>
                  <option value="detailed">Detailed - With service detection (~2-3 minutes)</option>
                  <option value="full">Full - All ports (~10+ minutes)</option>
                </select>
              </div>

              <div className="form-group">
                <label>Protocol</label>
                <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="BOTH">BOTH</option>
                </select>
              </div>

              <div className="form-group">
                <label>Ports (Optional)</label>
                <input
                  type="text"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="e.g., 80,443,8080 or 1-1000 or top1000"
                />
                <small>
                  Examples: 80,443 | 1-1000 | top1000 | all (Leave empty for default)
                </small>
              </div>

              <div className="scan-info">
                <h4>What will be scanned:</h4>
                <ul>
                  {scanType === 'basic' && (
                    <>
                      <li>Host discovery</li>
                      <li>Top 100 common ports (if not specified)</li>
                    </>
                  )}
                  {scanType === 'detailed' && (
                    <>
                      <li>Service version detection</li>
                      <li>OS detection</li>
                      <li>Top 1000 ports (if not specified)</li>
                    </>
                  )}
                  {scanType === 'full' && (
                    <>
                      <li>Service version detection</li>
                      <li>OS detection</li>
                      <li>Aggressive scripts</li>
                      <li>All 65535 ports (if not specified)</li>
                    </>
                  )}
                </ul>
              </div>
            </div>
            
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowScanModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleStartScan}>
                🚀 Start Scan
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Result Modal */}
      {showResultModal && selectedHost && (
        <DiscoveryResultModal
          host={selectedHost}
          scanId={currentScan?.scan_id}
          assetTypes={assetTypes}
          onClose={() => {
            setShowResultModal(false);
            setSelectedHost(null);
          }}
        />
      )}

      {/* Match Results Modal */}
      {showMatchModal && matchResults && (
        <div className="modal-overlay" onClick={() => setShowMatchModal(false)}>
          <div className="modal match-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>🔍 Check Matching Assets</h3>
              <button className="close-btn" onClick={() => setShowMatchModal(false)}>×</button>
            </div>

            <div className="modal-body">
              <div className="match-info">
                <p><strong>Recommendation:</strong> <span className={`recommendation ${matchResults.recommendation}`}>
                  {matchResults.recommendation === 'merge' ? '🔗 Merge with existing' :
                   matchResults.recommendation === 'create_new' ? '➕ Create new asset' :
                   '⚠️ Review carefully'}
                </span></p>
              </div>

              {matchResults.matches_found && matchResults.matches.length > 0 ? (
                <div className="matches-found">
                  <h4>Found {matchResults.matches.length} matching asset(s):</h4>
                  {matchResults.matches.map((match, index) => (
                    <div key={index} className="match-card">
                      <div className="match-header">
                        <strong>{match.asset_name || `Asset #${match.asset_id}`}</strong>
                        <span className="match-score">Match: {match.match_type}</span>
                      </div>
                      <div className="match-details">
                        <p><strong>IP:</strong> {match.ip_address || '-'}</p>
                        <p><strong>MAC:</strong> {match.mac_address || '-'}</p>
                        <p><strong>Hostname:</strong> {match.hostname || '-'}</p>
                      </div>
                      <div className="match-actions">
                        <button
                          className="btn btn-primary"
                          onClick={() => handleApprove(
                            pendingHosts.find(h => h.id === matchResults.host_id)?.id,
                            'merge_with_existing',
                            match.asset_id
                          )}
                        >
                          Merge with this asset
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-matches">
                  <p>✨ No matching assets found. This appears to be a new device.</p>
                </div>
              )}

              <div className="create-new-section">
                <h4>Or create as new asset:</h4>
                <button
                  className="btn btn-success"
                  onClick={() => {
                    const hostId = pendingHosts.find(h => matchResults.host_id === h.id)?.id;
                    if (hostId) {
                      handleApprove(hostId, 'create_new');
                    }
                  }}
                >
                  ➕ Create New Asset
                </button>
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowMatchModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AutoDiscovery;
