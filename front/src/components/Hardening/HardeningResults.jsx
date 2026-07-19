import { Fragment, useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults } from "../../store/hardeningSlice";
import HardenAllModal from "./HardenAllModal";
import FixSingleModal from "./FixSingleModal";
import { groupChecksByScope } from "./vdomScope";

export const HardeningResults = ({ sessionData, onClose, onNavigateToAuditing }) => {
    const dispatch = useDispatch();
    const { cisChecks, isLoading } = useSelector((state) => state.hardening);
    const [showHardenAllModal, setShowHardenAllModal] = useState(false);
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState(null);

    useEffect(() => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
    }, [sessionData?.session_id, sessionData?.device_type, dispatch]);

    const handleAuditingClick = () => {
        onClose();
        if (onNavigateToAuditing) {
            onNavigateToAuditing();
        } else {
            window.location.hash = "#operation-device";
        }
    };

    const handleHardenAll = () => setShowHardenAllModal(true);

    const handleModalSuccess = () => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
        setShowHardenAllModal(false);
    };

    const handleHardenSingle = (check) => {
        setSelectedCheck(check);
        setShowFixSingleModal(true);
    };

    const handleFixSingleSuccess = () => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
        setShowFixSingleModal(false);
        setSelectedCheck(null);
    };

    // Real audit statuses (this flow runs an audit right before this screen).
    // "Unknown" only when the row genuinely has no status.
    const getStatusBadge = (status) => {
        const s = status?.toString().toUpperCase();
        if (s === 'PASS' || s === 'PASSED') return <span className="result-badge result-success">Successful</span>;
        if (s === 'FAIL' || s === 'FAILED') return <span className="result-badge result-fail">Failed</span>;
        if (s === 'ERROR')                  return <span className="result-badge result-error">Error</span>;
        return <span className="result-badge result-unknown">Unknown</span>;
    };

    // Show the "audit your asset" hint only when no row carries a real status.
    const hasKnownStatus = (cisChecks || []).some((c) =>
        ['PASS', 'PASSED', 'FAIL', 'FAILED', 'ERROR'].includes(c.status?.toString().toUpperCase())
    );

    const getDeviceLabel = (dt) => {
        if (dt === 'fortinet')         return 'FortiGate';
        if (dt === 'linux' || dt?.startsWith('linux-'))  return 'Linux';
        if (dt === 'apache')           return 'Apache';
        if (dt === 'mongodb')          return 'MongoDB';
        if (dt?.startsWith('mssql-'))  return 'SQL Server';
        if (dt?.startsWith('windows-'))return 'Windows';
        return 'Cisco';
    };

    const totalChecks = cisChecks?.length || 0;

    // Split into Global vs per-VDOM groups (FortiGate multi-VDOM devices tag
    // each row with its vdom; flat devices get a single unlabeled group).
    const { hasVdom, groups } = groupChecksByScope(cisChecks);
    const colCount = hasVdom ? 5 : 4;

    return (
        <div className="modal-overlay result-modal-overlay" onClick={!showFixSingleModal && !showHardenAllModal ? onClose : undefined}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Hardening Result
                    </button>
                </div>

                {/* Hint box — only when statuses are genuinely unknown */}
                <div style={{ padding: '24px' }}>
                    {!isLoading && !hasKnownStatus && (
                        <div style={{
                            background: '#f9fafb',
                            border: '1px solid #e5e7eb',
                            borderRadius: '12px',
                            padding: '20px',
                            textAlign: 'center',
                            marginBottom: '20px'
                        }}>
                            <div style={{
                                fontSize: '16px',
                                color: '#374151',
                                marginBottom: '14px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                gap: '8px'
                            }}>
                                <span style={{ fontSize: '20px' }}>ℹ️</span>
                                <span>Status of CIS Benchmark section is unknown, audit your asset to specify status</span>
                            </div>
                            <button
                                onClick={handleAuditingClick}
                                style={{
                                    padding: '12px 32px',
                                    background: '#1e3a5f',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '8px',
                                    fontSize: '14px',
                                    fontWeight: '600',
                                    cursor: 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '8px'
                                }}
                            >
                                🔍 Auditing
                            </button>
                        </div>
                    )}

                    {/* Section Header with Harden All */}
                    <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '20px',
                        paddingBottom: '16px',
                        borderBottom: '2px solid #e5e7eb'
                    }}>
                        <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#1f2937', margin: 0 }}>
                            {getDeviceLabel(sessionData?.sub_device_type || sessionData?.device_type)} CIS Benchmark
                        </h3>
                        <button
                            onClick={handleHardenAll}
                            disabled={totalChecks === 0}
                            style={{
                                padding: '10px 24px',
                                background: totalChecks === 0 ? '#9ca3af' : '#1e3a5f',
                                color: 'white',
                                border: 'none',
                                borderRadius: '8px',
                                fontSize: '14px',
                                fontWeight: '600',
                                cursor: totalChecks === 0 ? 'not-allowed' : 'pointer'
                            }}
                        >
                            <img src="/icons/audit.svg" alt="" className="btn-icon" /> Harden All
                        </button>
                    </div>

                    {/* Table */}
                    <div className="result-table-wrapper">
                        {isLoading ? (
                            <div className="loading-spinner">Loading results...</div>
                        ) : (
                            <table className="result-table">
                                <thead>
                                <tr>
                                    <th>Section</th>
                                    {hasVdom && <th>VDOM</th>}
                                    <th>Recommendation</th>
                                    <th>Status</th>
                                    <th style={{ width: '120px' }}>Action</th>
                                </tr>
                                </thead>
                                <tbody>
                                {cisChecks && cisChecks.length > 0 ? (
                                    groups.map((group) => (
                                        <Fragment key={group.key}>
                                            {group.label && (
                                                <tr className="scope-group-row">
                                                    <td colSpan={colCount}>
                                                        {group.label}
                                                        <span className="scope-group-count">
                                                            {group.checks.length} check{group.checks.length !== 1 ? 's' : ''}
                                                        </span>
                                                    </td>
                                                </tr>
                                            )}
                                            {group.checks.map((check) => (
                                                <tr key={check.id}>
                                                    <td style={{ color: '#6b7280', fontWeight: '600' }}>{check.check_number}</td>
                                                    {hasVdom && (
                                                        <td>
                                                            {check.vdom && check.vdom !== 'global'
                                                                ? <span className="vdom-chip">{check.vdom}</span>
                                                                : <span style={{ color: '#9ca3af' }}>—</span>}
                                                        </td>
                                                    )}
                                                    <td>
                                                        <div className="recommendation-text">{check.check_title}</div>
                                                    </td>
                                                    <td>{getStatusBadge(check.status)}</td>
                                                    <td style={{ textAlign: 'center' }}>
                                                        {check.status?.toString().toUpperCase() === 'PASS' ? (
                                                            <span style={{ color: '#9ca3af' }}>—</span>
                                                        ) : (
                                                            <button
                                                                onClick={() => handleHardenSingle(check)}
                                                                style={{
                                                                    padding: '8px 18px',
                                                                    background: '#1e3a5f',
                                                                    color: 'white',
                                                                    border: 'none',
                                                                    borderRadius: '6px',
                                                                    fontSize: '13px',
                                                                    fontWeight: '600',
                                                                    cursor: 'pointer',
                                                                    whiteSpace: 'nowrap'
                                                                }}
                                                            >
                                                                <img src="/icons/audit.svg" alt="" className="btn-icon" /> Harden
                                                            </button>
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </Fragment>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={colCount} style={{ textAlign: 'center', padding: '40px' }}>
                                            No checks available
                                        </td>
                                    </tr>
                                )}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>
            </div>

            {/* Modals */}
            {showHardenAllModal && (
                <HardenAllModal
                    sessionId={sessionData.session_id}
                    assetId={sessionData.asset_id}
                    deviceType={sessionData.device_type}
                    checks={cisChecks}
                    onClose={() => setShowHardenAllModal(false)}
                    onSuccess={handleModalSuccess}
                />
            )}

            {showFixSingleModal && selectedCheck && (
                <FixSingleModal
                    check={selectedCheck}
                    assetId={sessionData?.asset_id}
                    sessionId={sessionData?.session_id}
                    deviceType={sessionData.device_type}
                    onClose={() => {
                        setShowFixSingleModal(false);
                        setSelectedCheck(null);
                    }}
                    onSuccess={handleFixSingleSuccess}
                />
            )}
        </div>
    );
};

export default HardeningResults;