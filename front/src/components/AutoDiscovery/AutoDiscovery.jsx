import React, { useState, useEffect, useRef, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    startScan,
    checkScanStatus,
    fetchScanHistory,
    fetchPendingHosts,
    deleteScan,
    clearError,
    fetchScanLogs,
    clearScanLogs,
} from "../../store/discoverySlice.jsx";
import { fetchAssetTypes } from "../../store/assetSlice.jsx";
import AutoDiscoveryDeleteModal from "./AutoDiscoveryDeleteModal.jsx";
import NewScanModal from "./NewScanModal.jsx";
import ScanHistoryTable from "./ScanHistoryTable.jsx";
import ScanResultsModal from "./ScanResultsModal.jsx";
import ApplyDiscoveryModal from "./ApplyDiscoveryModal.jsx";
import AutoDiscoveryAssetListModal from "./AutoDiscoveryAssetListModal";
import ScanLogPanel from "./ScanLogPanel.jsx";
import ScanErrorAlert from "./scanErrors.jsx";
import { getLicenseStatusThunk } from "../../store/licenseSlice";

import "../../assets/autoDiscoveryStyle/AutoDiscovery.css";

// Asset Management (including Auto Discovery) has no license entitlement, so
// this view is not license-gated (no LicenseLimitModal here).
const AutoDiscovery = () => {
    const dispatch = useDispatch();

    const { currentScan, scanHistory, loading, error, scanLogs } =
        useSelector((state) => state.discovery);

    const { assetTypes } = useSelector((state) => state.assets);

    const [deleteModal, setDeleteModal] = useState({
        isOpen: false,
        type: null,
        scanId: null,
        title: "",
        message: "",
    });

    const [showScanModal, setShowScanModal] = useState(false);
    const [showResultsModal, setShowResultsModal] = useState(false);
    const [selectedScan, setSelectedScan] = useState(null);
    const [showApproveModal, setShowApproveModal] = useState(false);
    const [selectedHostForApproval, setSelectedHostForApproval] = useState(null);
    const [showAssetListModal, setShowAssetListModal] = useState(false);

    const pollIntervalRef = useRef(null);
    const prevScanStatusRef = useRef(null);

    useEffect(() => {
        dispatch(fetchScanHistory());
        dispatch(fetchPendingHosts());
        dispatch(fetchAssetTypes());

        if (currentScan && (currentScan.status === "running" || currentScan.status === "pending")) {
            dispatch(checkScanStatus(currentScan.scan_id));
        }

        return () => {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, []);

    const handleStartScan = useCallback(
        (scanData) => {
            setShowScanModal(false);
            dispatch(startScan(scanData));
            setTimeout(() => {
                dispatch(fetchScanHistory());
                dispatch(getLicenseStatusThunk());
            }, 2000);
        },
        [dispatch],
    );

    const handleViewResults = useCallback(
        async (scan) => {
            const result = await dispatch(checkScanStatus(scan.scan_id));
            if (result.payload) {
                setSelectedScan(result.payload);
                setShowResultsModal(true);
            }
        },
        [dispatch],
    );

    // Detect transition to completed/failed/cancelled
    useEffect(() => {
        const prevStatus = prevScanStatusRef.current;
        const newStatus = currentScan?.status;
        prevScanStatusRef.current = newStatus;

        if (
            (prevStatus === "running" || prevStatus === "pending") &&
            (newStatus === "completed" ||
                newStatus === "failed" ||
                newStatus === "cancelled")
        ) {
            dispatch(fetchPendingHosts());
            dispatch(fetchScanHistory());
            if (currentScan) {
                setTimeout(() => handleViewResults(currentScan), 0);
            }
        }
    }, [currentScan?.status, dispatch]);

    // Poll for scan status and logs when running or pending
    useEffect(() => {
        if (currentScan && (currentScan.status === "running" || currentScan.status === "pending")) {
            dispatch(fetchScanLogs(currentScan.scan_id));
            pollIntervalRef.current = setInterval(() => {
                dispatch(checkScanStatus(currentScan.scan_id));
                dispatch(fetchScanLogs(currentScan.scan_id));
            }, 3000);
        } else {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
                pollIntervalRef.current = null;
            }
            dispatch(clearScanLogs());
        }

        return () => {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, [currentScan?.status, currentScan?.scan_id, dispatch]);

    const handleDeleteScan = (scanId) => {
        setDeleteModal({ isOpen: true, type: "SINGLE_SCAN", scanId: scanId });
    };

    const handleClearHistory = () => {
        setDeleteModal({ isOpen: true, type: "CLEAR_HISTORY", scanId: null });
    };

    const handleConfirmDelete = useCallback(() => {
        if (deleteModal.type === "SINGLE_SCAN" && deleteModal.scanId) {
            dispatch(deleteScan(deleteModal.scanId));
        } else if (deleteModal.type === "CLEAR_HISTORY") {
            scanHistory.forEach((scan) => {
                dispatch(deleteScan(scan.scan_id));
            });
        }
        setDeleteModal((prev) => ({ ...prev, isOpen: false }));
    }, [deleteModal, dispatch, scanHistory]);

    const handleApproveHost = useCallback((host) => {
        setSelectedHostForApproval(host);
        setShowApproveModal(true);
    }, []);

    const handleRefresh = useCallback(() => {
        dispatch(fetchScanHistory());
        dispatch(fetchPendingHosts());
    }, [dispatch]);

    const allScans = React.useMemo(() => {
        return scanHistory;
    }, [scanHistory]);

    // FIX: pending و running هر دو انیمیشن رو نشون میدن
    const hasRunningScan = React.useMemo(() => {
        if (currentScan?.status === "running" || currentScan?.status === "pending") return true;
        return allScans.some((scan) => scan.status === "running" || scan.status === "pending");
    }, [allScans, currentScan?.status]);

    return (
        <>
            <style>{`
                @keyframes bounce {
                    0%, 80%, 100% {
                        transform: scale(0);
                        opacity: 0.5;
                    }
                    40% {
                        transform: scale(1);
                        opacity: 1;
                    }
                }
            `}</style>

            <div className="discovery-container">
                <div className="discovery-header">
                    <div className="header-content">
                        <h1 className="page-title">Auto Discovery</h1>
                    </div>
                    <div className="header-actions">
                        <button
                            className="btn btn-primary"
                            onClick={() => setShowScanModal(true)}
                            disabled={currentScan && (currentScan.status === "running" || currentScan.status === "pending")}
                        >
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 5v14M5 12h14" />
                            </svg>
                            New Scan
                        </button>
                        {scanHistory.length > 0 && (
                            <button
                                className="btn btn-secondary"
                                onClick={handleClearHistory}
                                disabled={loading.history}
                            >
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                                </svg>
                                Clear History
                            </button>
                        )}
                        <button
                            className="btn btn-secondary"
                            onClick={handleRefresh}
                            disabled={loading.history || loading.pending}
                            title="Refresh"
                        >
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
                            </svg>
                            Refresh
                        </button>
                        <button
                            className="btn btn-dark"
                            onClick={() => setShowAssetListModal(true)}
                        >
                            Auto Discovery Asset list
                        </button>
                    </div>
                </div>

                {/* Error Alert — nmap-missing renders as an actionable warning */}
                <ScanErrorAlert error={error} onClose={() => dispatch(clearError())} />

                {/* Loading Card - نمایش در حین Scan */}
                {hasRunningScan &&
                    (() => {
                        const runningScan =
                            (currentScan?.status === "running" || currentScan?.status === "pending")
                                ? currentScan
                                : allScans.find((scan) => scan.status === "running" || scan.status === "pending");
                        if (!runningScan) return null;

                        return (
                            <div style={{ background: "#1e3a5f", borderRadius: "12px", padding: "24px", marginBottom: "24px", color: "white" }}>
                                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                                    <div style={{ fontSize: "16px", fontWeight: "600" }}>
                                        {runningScan.status === "pending" ? "Preparing scan..." : "Scanning:"} {runningScan.target || runningScan.ip_range}
                                    </div>
                                    <div style={{ background: "rgba(255, 255, 255, 0.2)", padding: "4px 12px", borderRadius: "6px", fontSize: "13px", fontWeight: "500" }}>
                                        {runningScan.scan_type === "well_known_ports"
                                            ? "Well-Know Ports(1-1024)"
                                            : runningScan.scan_type === "all_ports"
                                                ? "All Ports (1-65535)"
                                                : "Custom Ports"}
                                    </div>
                                </div>

                                <div style={{ fontSize: "14px", color: "rgba(255, 255, 255, 0.8)", marginBottom: "16px" }}>
                                    please wait... Scan started at{" "}
                                    {runningScan.started_at ? new Date(runningScan.started_at).toLocaleTimeString() : "now"}
                                </div>

                                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                                    <div style={{ width: "12px", height: "12px", background: "white", borderRadius: "50%", animation: "bounce 1.4s infinite ease-in-out both", animationDelay: "-0.32s" }}></div>
                                    <div style={{ width: "12px", height: "12px", background: "white", borderRadius: "50%", animation: "bounce 1.4s infinite ease-in-out both", animationDelay: "-0.16s" }}></div>
                                    <div style={{ width: "12px", height: "12px", background: "white", borderRadius: "50%", animation: "bounce 1.4s infinite ease-in-out both" }}></div>
                                </div>

                                <ScanLogPanel logs={scanLogs} />
                            </div>
                        );
                    })()}

                {/* Scan History */}
                <div className="scan-history-section">
                    {allScans.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-icon">
                                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                                    <circle cx="11" cy="11" r="8" />
                                    <path d="M21 21l-4.35-4.35" />
                                </svg>
                            </div>
                            <h3>No scans yet. Start your first scan!</h3>
                        </div>
                    ) : (
                        <ScanHistoryTable
                            scans={allScans}
                            loading={loading.history}
                            onViewResults={handleViewResults}
                            onDelete={handleDeleteScan}
                        />
                    )}
                </div>

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
                                {currentScan && (currentScan.status === "running" || currentScan.status === "pending") && (
                                    <div className="activity-item activity-running">
                                        <div className="activity-icon">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
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
                                    <div key={scan.scan_id} className={`activity-item activity-${scan.status}`}>
                                        <div className="activity-icon">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                                                <circle cx="12" cy="12" r="10" />
                                            </svg>
                                        </div>
                                        <div className="activity-content">
                                            <p className="activity-message">
                                                {scan.status === "completed" && `Scan completed: Found ${scan.hosts_up || 0} hosts`}
                                                {scan.status === "failed" && `Scan failed: ${scan.target}`}
                                                {scan.status === "running" && `Scanning: ${scan.target}`}
                                                {scan.status === "pending" && `Pending: ${scan.target}`}
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
                    <NewScanModal onClose={() => setShowScanModal(false)} onSubmit={handleStartScan} />
                )}

                {showResultsModal && selectedScan && (
                    <ScanResultsModal
                        scan={selectedScan}
                        onClose={() => { setShowResultsModal(false); setSelectedScan(null); }}
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

            <AutoDiscoveryDeleteModal
                isOpen={deleteModal.isOpen}
                onCancel={() => setDeleteModal((prev) => ({ ...prev, isOpen: false }))}
                onConfirm={handleConfirmDelete}
                title={deleteModal.type === "SINGLE_SCAN" ? "Delete Scan" : "Clear History"}
                message={
                    deleteModal.type === "SINGLE_SCAN"
                        ? "Are you sure you want to delete this scan?"
                        : "Are you sure you want to clear all scan history?"
                }
            />
        </>
    );
};

export default AutoDiscovery;