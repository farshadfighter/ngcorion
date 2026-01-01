/**
 * Auto Discovery Page
 * Network scanning and asset discovery management
 */

import React, { useState, useEffect, useRef, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
  startScan,
  checkScanStatus,
  fetchScanHistory,
  fetchPendingHosts,
  deleteScan,
  clearError,
  stopScanning,
} from "../../store/discoverySlice.jsx";
import { fetchAssetTypes } from "../../store/assetSlice.jsx";

import NewScanModal from "./NewScanModal.jsx";
import ScanHistoryTable from "./ScanHistoryTable.jsx";
import ScanResultsModal from "./ScanResultsModal.jsx";
import ApplyDiscoveryModal from "./ApplyDiscoveryModal.jsx";
import AutoDiscoveryAssetListModal from "./AutoDiscoveryAssetListModal";
import "../../assets/autoDiscoveryStyle/AutoDiscovery.css";

const AutoDiscovery = () => {
  const dispatch = useDispatch();

  // Redux state
  const { currentScan, scanHistory, pendingHosts, loading, error } =
    useSelector((state) => state.discovery);

  const { assetTypes } = useSelector((state) => state.assets);

  // Local state
  const [showScanModal, setShowScanModal] = useState(false);
  const [showResultsModal, setShowResultsModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [selectedHostForApproval, setSelectedHostForApproval] = useState(null);
  const [showAssetListModal, setShowAssetListModal] = useState(false);

  // Polling ref
  const pollIntervalRef = useRef(null);

  // Load initial data and restore running scan state
  useEffect(() => {
    dispatch(fetchScanHistory());
    dispatch(fetchPendingHosts());
    dispatch(fetchAssetTypes());

    // If there's a restored scan from localStorage, immediately check its status
    if (currentScan && currentScan.status === "running") {
      dispatch(checkScanStatus(currentScan.scan_id));
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [dispatch]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll for scan status when running
  useEffect(() => {
    if (currentScan && currentScan.status === "running") {
      pollIntervalRef.current = setInterval(() => {
        dispatch(checkScanStatus(currentScan.scan_id));
      }, 3000);
    } else {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }

      // 🔧 FIX: Refresh pending hosts when scan completes با تاخیر برای اطمینان از پردازش backend
      if (currentScan && currentScan.status === "completed") {
        // تاخیر 1.5 ثانیه برای اطمینان از اینکه backend پردازش رو تموم کرده
        setTimeout(() => {
          dispatch(fetchPendingHosts());
          dispatch(fetchScanHistory());
        }, 1500);
      }
    }

    // 🔧 FIX: Cleanup function با پاک کردن کامل reference
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [currentScan, dispatch]);

  // Handle starting a new scan
  const handleStartScan = useCallback(
    (scanData) => {
      dispatch(startScan(scanData));
      setShowScanModal(false);
    },
    [dispatch]
  );

  // Handle viewing scan results
  const handleViewResults = useCallback(
    async (scan) => {
      const result = await dispatch(checkScanStatus(scan.scan_id));
      if (result.payload) {
        setSelectedScan(result.payload);
        setShowResultsModal(true);
      }
    },
    [dispatch]
  );

  // Handle deleting a scan
  const handleDeleteScan = useCallback(
    (scanId) => {
      if (window.confirm("Are you sure you want to delete this scan?")) {
        dispatch(deleteScan(scanId));
      }
    },
    [dispatch]
  );

  // Handle clearing all history
  const handleClearHistory = useCallback(() => {
    if (window.confirm("Are you sure you want to clear all scan history?")) {
      scanHistory.forEach((scan) => {
        dispatch(deleteScan(scan.scan_id));
      });
    }
  }, [dispatch, scanHistory]);

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
    if (!currentScan || currentScan.status !== "running") return 0;
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
        </div>
        <div className="header-actions">
          <button
            className="btn btn-primary"
            onClick={() => setShowScanModal(true)}
            disabled={loading.scan}
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M12 5v14M5 12h14" />
            </svg>
            New Scan
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleRefresh}
            disabled={loading.history || loading.pending}
            title="Refresh"
          >
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
            </svg>
            Refresh
          </button>
          {scanHistory.length > 0 && (
            <button
              className="btn btn-secondary"
              onClick={handleClearHistory}
              disabled={loading.history}
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
              </svg>
              Clear History
            </button>
          )}
          <button
            className="btn btn-dark"
            onClick={() => setShowAssetListModal(true)}
          >
            Auto Discovery Asset list
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert alert-error">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="12" cy="12" r="10" />
            <path d="M15 9l-6 6M9 9l6 6" />
          </svg>
          <span>{error}</span>
          <button
            className="alert-close"
            onClick={() => dispatch(clearError())}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Active Scan Progress or Scan History */}
      {currentScan && currentScan.status === "running" ? (
        <div className="scan-progress-card">
          <div className="scan-progress-header">
            <div className="scan-info">
              <div className="scan-icon scanning">
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 6v6l4 2" />
                </svg>
              </div>
              <div className="scan-details">
                <h3>Scanning: {currentScan.target}</h3>
                <p>
                  please wait ... Scan started at{" "}
                  {new Date(currentScan.started_at).toLocaleTimeString()}
                </p>
              </div>
            </div>
            <div className="scan-meta">
              <span className="scan-type-badge">
                {getScanTypeLabel(currentScan.scan_type)}
              </span>
              <button
                className="btn btn-sm btn-danger"
                onClick={() => {
                  dispatch(stopScanning());

                  if (pollIntervalRef.current) {
                    clearInterval(pollIntervalRef.current);
                  }
                }}
              >
                Stop Scan
              </button>
            </div>
          </div>
          <div className="scan-progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${getScanProgress()}%` }}
            />
          </div>
        </div>
      ) : (
        <div className="scan-history-section">
          {scanHistory.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">
                <svg
                  width="64"
                  height="64"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                >
                  <circle cx="11" cy="11" r="8" />
                  <path d="M21 21l-4.35-4.35" />
                </svg>
              </div>
              <h3>No scans yet. Start your first scan!</h3>
            </div>
          ) : (
            <ScanHistoryTable
              scans={scanHistory}
              loading={loading.history}
              onViewResults={handleViewResults}
              onDelete={handleDeleteScan}
            />
          )}
        </div>
      )}

      {/* Activity Log Section */}
      <div className="activity-log-section">
        <div className="activity-log-header">
          <h3>Activity Log</h3>
        </div>
        <div className="activity-log-content">
          {scanHistory.length === 0 && !currentScan ? (
            <div className="activity-empty">
              <p>No activity yet. Start a scan to see logs here.</p>
            </div>
          ) : (
            <div className="activity-log-list">
              {currentScan && currentScan.status === "running" && (
                <div className="activity-item activity-running">
                  <div className="activity-icon">
                    <svg
                      width="16"
                      height="16"
                      viewBox="0 0 24 24"
                      fill="currentColor"
                    >
                      <circle cx="12" cy="12" r="10" />
                    </svg>
                  </div>
                  <div className="activity-content">
                    <p className="activity-message">
                      Scan in progress: {currentScan.target}
                    </p>
                    <span className="activity-time">
                      {new Date(currentScan.started_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              )}
              {scanHistory.slice(0, 10).map((scan) => (
                <div
                  key={scan.scan_id}
                  className={`activity-item activity-${scan.status}`}
                >
                  <div className="activity-icon">
                    <svg
                      width="16"
                      height="16"
                      viewBox="0 0 24 24"
                      fill="currentColor"
                    >
                      <circle cx="12" cy="12" r="10" />
                    </svg>
                  </div>
                  <div className="activity-content">
                    <p className="activity-message">
                      {scan.status === "completed" &&
                        `Scan completed: Found ${scan.hosts_up || 0} hosts`}
                      {scan.status === "failed" &&
                        `Scan failed: ${scan.target}`}
                      {scan.status === "running" && `Scanning: ${scan.target}`}
                    </p>
                    <p className="activity-details">{scan.target}</p>
                    <span className="activity-time">
                      {scan.completed_at
                        ? new Date(scan.completed_at).toLocaleTimeString()
                        : new Date(scan.started_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
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
            dispatch(fetchPendingHosts());
          }}
        />
      )}

      {showAssetListModal && (
        <AutoDiscoveryAssetListModal
          onClose={() => setShowAssetListModal(false)}
          onScanAsset={handleStartScan}
          isScanning={loading.scan}
        />
      )}
    </div>
  );
};

// Helper function for scan type labels
const getScanTypeLabel = (type) => {
  const labels = {
    all_ports: "All Ports",
    well_known_ports: "Well-Know Ports(1-1024)",
    custom_ports: "Custom",
  };
  return labels[type] || type;
};

export default AutoDiscovery;
