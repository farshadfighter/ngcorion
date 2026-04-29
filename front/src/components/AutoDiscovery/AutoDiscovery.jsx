import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    startScan,
    checkScanStatus,
    fetchScanHistory,
    fetchPendingHosts,
    deleteScan,
    clearError,
} from '../../store/discoverySlice.jsx';
import { fetchAssetTypes } from  "../../store/assetSlice.jsx";

import NewScanModal from './NewScanModal.jsx';
import ScanHistoryTable from './ScanHistoryTable.jsx';
import ScanResultsModal from './ScanResultsModal.jsx';
import ApplyDiscoveryModal from './ApplyDiscoveryModal.jsx';
import AutoDiscoveryAssetListModal from './AutoDiscoveryAssetListModal';
import { LicenseBadge } from "../License/LicenseBadge";
import { LicenseLimitModal } from "../License/LicenseLimitModal";

import '../../assets/autoDiscoveryStyle/AutoDiscovery.css';
const [showLicenseModal, setShowLicenseModal] = useState(false);

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
    const [showAssetListModal, setShowAssetListModal] = useState(false);

    // Polling ref
    const pollIntervalRef = useRef(null);

    // Load initial data and restore running scan state
    useEffect(() => {
        dispatch(fetchScanHistory());
        dispatch(fetchPendingHosts());
        dispatch(fetchAssetTypes());

        // If there's a restored scan from localStorage, immediately check its status
        if (currentScan && currentScan.status === 'running') {
            dispatch(checkScanStatus(currentScan.scan_id));
        }

        return () => {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, []);

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

        setShowScanModal(false);


        dispatch(startScan(scanData));

        setTimeout(() => {
            dispatch(fetchScanHistory());
        }, 2000);
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

    // Handle clearing all history
    const handleClearHistory = useCallback(() => {
        if (window.confirm('Are you sure you want to clear all scan history?')) {
            scanHistory.forEach(scan => {
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

    // Merge currentScan into scanHistory for display
    const allScans = React.useMemo(() => {
        return scanHistory;
    }, [scanHistory]);

    // چک کردن آیا scan در حال اجراست
    const hasRunningScan = React.useMemo(() => {
        return allScans.some(scan => scan.status === 'running');
    }, [allScans]);
    const handleLicenseLimitReached = useCallback(() => {
        setShowLicenseModal(true);
    }, []);

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
                {/* Page Header - Simple, always the same */}
                <div className="discovery-header">
                    <div className="header-content">
                        <h1 className="page-title">Auto Discovery</h1>
                    </div>
                    <div className="header-actions">
                        <LicenseBadge
                            module="autoDiscovery"
                            onLimitReached={handleLicenseLimitReached}
                        />

                        <button
                            className="btn btn-primary"
                            onClick={() => setShowScanModal(true)}
                            disabled={currentScan && currentScan.status === 'running'} >

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

                {/* Loading Card - نمایش در حین Scan */}
                {hasRunningScan && (() => {
                    const runningScan = allScans.find(scan => scan.status === 'running');
                    if (!runningScan) return null;

                    return (
                        <div style={{
                            background: '#1e3a5f',
                            borderRadius: '12px',
                            padding: '24px',
                            marginBottom: '24px',
                            color: 'white'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                                <div style={{ fontSize: '16px', fontWeight: '600' }}>
                                    Scanning: {runningScan.target || runningScan.ip_range}
                                </div>
                                <div style={{
                                    background: 'rgba(255, 255, 255, 0.2)',
                                    padding: '4px 12px',
                                    borderRadius: '6px',
                                    fontSize: '13px',
                                    fontWeight: '500'
                                }}>
                                    {runningScan.scan_type === 'well_known_ports' ? 'Well-Know Ports(1-1024)' :
                                        runningScan.scan_type === 'all_ports' ? 'All Ports (1-65535)' :
                                            'Custom Ports'}
                                </div>
                            </div>

                            <div style={{ fontSize: '14px', color: 'rgba(255, 255, 255, 0.8)', marginBottom: '16px' }}>
                                please wait... Scan started at {runningScan.started_at ? new Date(runningScan.started_at).toLocaleTimeString() : 'now'}
                            </div>

                            {/* انیمیشن 3 دایره */}
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <div style={{
                                    width: '12px',
                                    height: '12px',
                                    background: 'white',
                                    borderRadius: '50%',
                                    animation: 'bounce 1.4s infinite ease-in-out both',
                                    animationDelay: '-0.32s'
                                }}></div>
                                <div style={{
                                    width: '12px',
                                    height: '12px',
                                    background: 'white',
                                    borderRadius: '50%',
                                    animation: 'bounce 1.4s infinite ease-in-out both',
                                    animationDelay: '-0.16s'
                                }}></div>
                                <div style={{
                                    width: '12px',
                                    height: '12px',
                                    background: 'white',
                                    borderRadius: '50%',
                                    animation: 'bounce 1.4s infinite ease-in-out both'
                                }}></div>
                            </div>
                        </div>
                    );
                })()}

                {/* Scan History - Always shows, including running scans */}
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
                                {currentScan && currentScan.status === 'running' && (
                                    <div className="activity-item activity-running">
                                        <div className="activity-icon">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                                                <circle cx="12" cy="12" r="10" />
                                            </svg>
                                        </div>
                                        <div className="activity-content">
                                            <p className="activity-message">Scan in progress: {currentScan.target}</p>
                                            <span className="activity-time">{new Date(currentScan.started_at).toLocaleTimeString()}</span>
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
                                                {scan.status === 'completed' && `Scan completed: Found ${scan.hosts_up || 0} hosts`}
                                                {scan.status === 'failed' && `Scan failed: ${scan.target}`}
                                                {scan.status === 'running' && `Scanning: ${scan.target}`}
                                            </p>
                                            <p className="activity-details">{scan.target}</p>
                                            <span className="activity-time">
                      {scan.completed_at ? new Date(scan.completed_at).toLocaleTimeString() : new Date(scan.started_at).toLocaleTimeString()}
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
                {showLicenseModal && (
                    <LicenseLimitModal
                        isOpen={showLicenseModal}
                        onClose={() => setShowLicenseModal(false)}
                        module="autoDiscovery"
                        onNavigateToLicence={onNavigateToLicence}
                    />
                )}

            </div>
        </>
    );
};

export default AutoDiscovery;