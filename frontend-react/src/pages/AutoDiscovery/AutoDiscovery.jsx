/**
 * Auto Discovery Page
 * Network scanning and asset discovery management
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  startScan,
  checkScanStatus,
  fetchScanHistory,
  fetchPendingHosts,
  deleteScan,
  clearError,
  stopScanning,
} from '../../store/slices/discoverySlice';
import { fetchAssetTypes } from '../../store/slices/assetsSlice';

import NewScanModal from './components/NewScanModal';
import PendingHostsTable from './components/PendingHostsTable';
import ScanHistoryTable from './components/ScanHistoryTable';
import ScanResultsModal from './components/ScanResultsModal';
import ApplyDiscoveryModal from './components/ApplyDiscoveryModal';
import AssetListTable from './components/AssetListTable';

import './AutoDiscovery.css';

const AutoDiscovery = () => {
  const dispatch = useDispatch();

  // Redux state
  const {
    currentScan,
    scanHistory,
    pendingHosts,
    loading,
    error,
  } = useSelector((state) => state.discovery);

  const { assetTypes } = useSelector((state) => state.assets);

  // Local state
  const [showScanModal, setShowScanModal] = useState(false);
  const [showResultsModal, setShowResultsModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [selectedHostForApproval, setSelectedHostForApproval] = useState(null);
  const [activeTab, setActiveTab] = useState('assets'); // 'assets', 'pending', or 'history'

  // Polling ref
  const pollIntervalRef = useRef(null);

  // Load initial data
  useEffect(() => {
    dispatch(fetchScanHistory());
    dispatch(fetchPendingHosts());
    dispatch(fetchAssetTypes());

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [dispatch]);

  // Poll for scan status when running
  useEffect(() => {
    if (currentScan && currentScan.status === 'running') {
      pollIntervalRef.current = setInterval(() => {
        dispatch(checkScanStatus(currentScan.scan_id));
      }, 3000);
    } else {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }

      // Refresh pending hosts when scan completes
      if (currentScan && currentScan.status === 'completed') {
        dispatch(fetchPendingHosts());
        dispatch(fetchScanHistory());
      }
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [currentScan, dispatch]);

  // Handle starting a new scan
  const handleStartScan = useCallback((scanData) => {
    dispatch(startScan(scanData));
    setShowScanModal(false);
  }, [dispatch]);

  // Handle viewing scan results
  const handleViewResults = useCallback(async (scan) => {
    const result = await dispatch(checkScanStatus(scan.scan_id));
    if (result.payload) {
      setSelectedScan(result.payload);
      setShowResultsModal(true);
    }
  }, [dispatch]);

  // Handle deleting a scan
  const handleDeleteScan = useCallback((scanId) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      dispatch(deleteScan(scanId));
    }
  }, [dispatch]);

  // Handle host approval workflow
  const handleApproveHost = useCallback((host) => {
    setSelectedHostForApproval(host);
    setShowApproveModal(true);
  }, []);

  // Handle refresh
  const handleRefresh = useCallback(() => {
    dispatch(fetchScanHistory());
    dispatch(fetchPendingHosts());
  }, [dispatch]);

  // Calculate scan progress percentage (estimated)
  const getScanProgress = () => {
    if (!currentScan || currentScan.status !== 'running') return 0;
    const elapsed = Date.now() - new Date(currentScan.started_at).getTime();
    // Estimate based on scan type
    const estimates = {
      all_ports: 300000, // 5 min
      well_known_ports: 60000, // 1 min
      custom_ports: 30000, // 30 sec
    };
    const estimate = estimates[currentScan.scan_type] || 60000;
    return Math.min(95, (elapsed / estimate) * 100);
  };

  return (
    <div className="discovery-container">
      {/* Page Header */}
      <div className="discovery-header">
        <div className="header-content">
          <h1 className="page-title">Auto Discovery</h1>
          <p className="page-subtitle">
            Scan your network to discover and manage assets automatically
          </p>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-icon"
            onClick={handleRefresh}
            disabled={loading.history || loading.pending}
            title="Refresh"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
            </svg>
          </button>
          <button
            className="btn btn-primary"
            onClick={() => setShowScanModal(true)}
            disabled={loading.scan}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="M21 21l-4.35-4.35" />
            </svg>
            New Scan
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert alert-error">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M15 9l-6 6M9 9l6 6" />
          </svg>
          <span>{error}</span>
          <button className="alert-close" onClick={() => dispatch(clearError())}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Active Scan Progress */}
      {currentScan && currentScan.status === 'running' && (
        <div className="scan-progress-card">
          <div className="scan-progress-header">
            <div className="scan-info">
              <div className="scan-icon scanning">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 6v6l4 2" />
                </svg>
              </div>
              <div className="scan-details">
                <h3>{currentScan.job_name || 'Network Scan'}</h3>
                <p>Target: <strong>{currentScan.target}</strong></p>
              </div>
            </div>
            <div className="scan-meta">
              <span className="scan-type-badge">{getScanTypeLabel(currentScan.scan_type)}</span>
              <button
                className="btn btn-sm btn-danger"
                onClick={() => {
                  dispatch(stopScanning());
                  if (pollIntervalRef.current) {
                    clearInterval(pollIntervalRef.current);
                  }
                }}
              >
                Stop
              </button>
            </div>
          </div>
          <div className="scan-progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${getScanProgress()}%` }}
            />
          </div>
          <p className="scan-progress-text">
            Scanning in progress... Started at {new Date(currentScan.started_at).toLocaleTimeString()}
          </p>
        </div>
      )}

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon pending">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{pendingHosts.length}</span>
            <span className="stat-label">Pending Approval</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon scans">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
              <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" />
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{scanHistory.length}</span>
            <span className="stat-label">Total Scans</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon completed">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
              <path d="M22 4L12 14.01l-3-3" />
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">
              {scanHistory.filter(s => s.status === 'completed').length}
            </span>
            <span className="stat-label">Completed</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon hosts">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <path d="M8 21h8M12 17v4" />
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">
              {scanHistory.reduce((acc, s) => acc + (s.hosts_up || 0), 0)}
            </span>
            <span className="stat-label">Hosts Found</span>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="tab-navigation">
        <button
          className={`tab-btn ${activeTab === 'assets' ? 'active' : ''}`}
          onClick={() => setActiveTab('assets')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
            <path d="M8 21h8M12 17v4" />
          </svg>
          Asset List
        </button>
        <button
          className={`tab-btn ${activeTab === 'pending' ? 'active' : ''}`}
          onClick={() => setActiveTab('pending')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4" />
          </svg>
          Pending Hosts
          {pendingHosts.length > 0 && (
            <span className="tab-badge">{pendingHosts.length}</span>
          )}
        </button>
        <button
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M12 6v6l4 2" />
          </svg>
          Scan History
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'assets' && (
          <AssetListTable
            onScanAsset={handleStartScan}
            isScanning={loading.scan}
          />
        )}
        {activeTab === 'pending' && (
          <PendingHostsTable
            hosts={pendingHosts}
            loading={loading.pending}
            onApprove={handleApproveHost}
            assetTypes={assetTypes}
          />
        )}
        {activeTab === 'history' && (
          <ScanHistoryTable
            scans={scanHistory}
            loading={loading.history}
            onViewResults={handleViewResults}
            onDelete={handleDeleteScan}
          />
        )}
      </div>

      {/* Modals */}
      {showScanModal && (
        <NewScanModal
          onClose={() => setShowScanModal(false)}
          onSubmit={handleStartScan}
          isLoading={loading.scan}
        />
      )}

      {showResultsModal && selectedScan && (
        <ScanResultsModal
          scan={selectedScan}
          onClose={() => {
            setShowResultsModal(false);
            setSelectedScan(null);
          }}
        />
      )}

      {showApproveModal && selectedHostForApproval && (
        <ApplyDiscoveryModal
          host={selectedHostForApproval}
          assetTypes={assetTypes}
          onClose={() => {
            setShowApproveModal(false);
            setSelectedHostForApproval(null);
            dispatch(fetchPendingHosts()); // Refresh the list
          }}
        />
      )}
    </div>
  );
};

// Helper function for scan type labels
const getScanTypeLabel = (type) => {
  const labels = {
    all_ports: 'All Ports',
    well_known_ports: 'Well-Known',
    custom_ports: 'Custom',
  };
  return labels[type] || type;
};

export default AutoDiscovery;
