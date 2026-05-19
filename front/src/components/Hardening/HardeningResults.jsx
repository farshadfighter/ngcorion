import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults } from "../../store/hardeningSlice";
import HardenAllModal from "./HardenAllModal";
import FixSingleModal from "./FixSingleModal";

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

    const getStatusBadge = () => {
        return <span className="result-badge result-unknown">unknown</span>;
    };

    const getDeviceLabel = (dt) => {
        if (dt === 'fortinet')         return 'FortiGate';
        if (dt?.startsWith('linux-'))  return 'Linux';
        if (dt === 'apache')           return 'Apache';
        if (dt === 'mongodb')          return 'MongoDB';
        if (dt?.startsWith('mssql-'))  return 'SQL Server';
        if (dt?.startsWith('windows-'))return 'Windows';
        return 'Cisco';
    };

    const totalChecks = cisChecks?.length || 0;

    return (
        <div className="modal-overlay result-modal-overlay" onClick={onClose}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Hardening Result
                    </button>
                </div>

                {/* Warning Box */}
                <div style={{ padding: '40px' }}>
                    <div style={{
                        background: '#f9fafb',
                        border: '1px solid #e5e7eb',
                        borderRadius: '12px',
                        padding: '32px',
                        textAlign: 'center',
                        marginBottom: '40px'
                    }}>
                        <div style={{
                            fontSize: '16px',
                            color: '#374151',
                            marginBottom: '20px',
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
                            {getDeviceLabel(sessionData?.device_type)} CIS Benchmark
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
                                    <th>Recommendation</th>
                                    <th>Status</th>
                                    <th style={{ width: '120px' }}>Action</th>
                                </tr>
                                </thead>
                                <tbody>
                                {cisChecks && cisChecks.length > 0 ? (
                                    cisChecks.map((check) => (
                                        <tr key={check.id}>
                                            <td style={{ color: '#6b7280', fontWeight: '600' }}>{check.check_number}</td>
                                            <td>
                                                <div className="recommendation-text">{check.check_title}</div>
                                            </td>
                                            <td>{getStatusBadge(check.status)}</td>
                                            <td style={{ textAlign: 'center' }}>
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
                                                        cursor: 'pointer'
                                                    }}
                                                >
                                                    <img src="/icons/audit.svg" alt="" className="btn-icon" /> Harden
                                                </button>
                                            </td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan="4" style={{ textAlign: 'center', padding: '40px' }}>
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
                    onClose={() => setShowHardenAllModal(false)}
                    onSuccess={handleModalSuccess}
                />
            )}

            {showFixSingleModal && selectedCheck && (
                <FixSingleModal
                    check={selectedCheck}
                    assetId={sessionData?.asset_id}
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