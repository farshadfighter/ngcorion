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
  } = useSelector((state) => state.discovery);
  
  const { assetTypes } = useSelector((state) => state.assets);
  
  // Local state
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedHost, setSelectedHost] = useState(null);
  const [showResultModal, setShowResultModal] = useState(false);
  
  // Polling interval ref
  const pollIntervalRef = useRef(null);
  
  // Load scan history and asset types on mount
  useEffect(() => {
    dispatch(fetchAllScans());
    dispatch(fetchAssetTypes());
    
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
    
    dispatch(startScan({ target: target.trim(), scanType }));
    setShowScanModal(false);
  };
  
  // Handle host click - check if matches existing asset
  const handleHostClick = async (host) => {
    setSelectedHost(host);
    await dispatch(matchIpToAsset(host.ip_address));
    setShowResultModal(true);
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
      
      {/* Discovered Hosts */}
      {discoveredHosts.length > 0 && (
        <div className="discovered-hosts">
          <h2>📡 Discovered Hosts ({discoveredHosts.length})</h2>
          <div className="hosts-grid">
            {discoveredHosts.map((host, index) => (
              <div 
                key={index} 
                className="host-card"
                onClick={() => handleHostClick(host)}
              >
                <div className="host-header">
                  <span className="host-ip">{host.ip_address}</span>
                  <span className={`host-state ${host.state}`}>{host.state}</span>
                </div>
                
                {host.hostname && (
                  <div className="host-detail">
                    <span className="label">Hostname:</span>
                    <span className="value">{host.hostname}</span>
                  </div>
                )}
                
                {host.vendor && (
                  <div className="host-detail">
                    <span className="label">Vendor:</span>
                    <span className="value">{host.vendor}</span>
                  </div>
                )}
                
                {host.os_name && (
                  <div className="host-detail">
                    <span className="label">OS:</span>
                    <span className="value">
                      {host.os_name} {host.os_version || ''}
                      {host.os_accuracy && ` (${host.os_accuracy}%)`}
                    </span>
                  </div>
                )}
                
                {host.mac_address && (
                  <div className="host-detail">
                    <span className="label">MAC:</span>
                    <span className="value">{host.mac_address}</span>
                  </div>
                )}
                
                <div className="host-detail">
                  <span className="label">Type Guess:</span>
                  <span className="value type-badge">
                    {host.suggested_asset_type || 'unknown'}
                  </span>
                </div>
                
                <div className="host-ports">
                  <span className="label">Open Ports ({host.ports?.length || 0}):</span>
                  <div className="ports-list">
                    {host.ports?.slice(0, 10).map((port, i) => (
                      <span key={i} className="port-badge">
                        {port.port}/{port.protocol}
                        {port.service && ` (${port.service})`}
                      </span>
                    ))}
                    {host.ports?.length > 10 && (
                      <span className="port-more">+{host.ports.length - 10} more</span>
                    )}
                  </div>
                </div>
                
                <button className="btn btn-small btn-action">
                  Click to Apply →
                </button>
              </div>
            ))}
          </div>
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
              
              <div className="scan-info">
                <h4>What will be scanned:</h4>
                <ul>
                  {scanType === 'basic' && (
                    <>
                      <li>Top 100 common ports</li>
                      <li>Host discovery</li>
                    </>
                  )}
                  {scanType === 'detailed' && (
                    <>
                      <li>Top 1000 ports</li>
                      <li>Service version detection</li>
                      <li>Host discovery</li>
                    </>
                  )}
                  {scanType === 'full' && (
                    <>
                      <li>All 65535 ports</li>
                      <li>Service version detection</li>
                      <li>Aggressive scripts</li>
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
    </div>
  );
};

export default AutoDiscovery;
