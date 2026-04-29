import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults } from "../../store/hardeningSlice";
import HardenAllModal from './HardenAllModal';
import FixSingleModal from './FixSingleModal';

export const FixUnsuccessfulResults = ({ sessionData, onClose, onNavigateToAuditing }) => {
    const dispatch = useDispatch();
    const { cisChecks, isLoading } = useSelector((state) => state.hardening);
    const [showHardenAllModal, setShowHardenAllModal] = useState(false);
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState(null);
    const [activeTab, setActiveTab] = useState('audit');

    useEffect(() => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
    }, [sessionData?.session_id, sessionData?.device_type, dispatch]);

    const handleHardenAll = () => {
        setShowHardenAllModal(true);
    };

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

    const getStatusBadge = (status) => {
        const normalizedStatus = status?.toString().toUpperCase();
        if (normalizedStatus === "PASS") {
            return <span className="result-badge result-success">successful</span>;
        } else if (normalizedStatus === "FAIL") {
            return <span className="result-badge result-fail">Unsuccessful</span>;
        } else {
            return <span className="result-badge result-unknown">unknown</span>;
        }
    };

    const totalChecks = cisChecks?.length || 0;
    const passedChecks = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'PASS').length || 0;
    const failedChecks = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL').length || 0;
    const compliancePercentage = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonCompliancePercentage = totalChecks > 0 ? Math.round((failedChecks / totalChecks) * 100) : 0;

    const displayedChecks = activeTab === 'unsuccessful'
        ? cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL')
        : cisChecks;

    return (
        <div className="modal-overlay result-modal-overlay" onClick={onClose}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Hardening Result
                    </button>
                </div>

                {/* Statistics Cards */}
                <div className="result-stats-container">
                    {/* Row 1: کارت‌های آماری */}
                    <div className="result-card result-card-success" style={{
                        background: 'linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%)',
                        border: '2px solid #6ee7b7'
                    }}>
                        <div className="card-percent" style={{
                            fontSize: '32px',
                            fontWeight: '700',
                            color: '#059669',
                            marginBottom: '8px'
                        }}>
                            {compliancePercentage}% | {passedChecks}
                        </div>
                        <div className="card-label">Conformity</div>
                    </div>

                    <div className="result-card result-card-danger" style={{
                        background: 'linear-gradient(135deg, #fee2e2 0%, #fecaca 100%)',
                        border: '2px solid #fca5a5'
                    }}>
                        <div className="card-percent" style={{
                            fontSize: '32px',
                            fontWeight: '700',
                            color: '#dc2626',
                            marginBottom: '8px'
                        }}>
                            {nonCompliancePercentage}% | {failedChecks}
                        </div>
                        <div className="card-label">Non-Conformity</div>
                    </div>

                    <div className="result-card result-card-total">
                        <div className="card-number">{totalChecks}</div>
                        <div className="card-label">Total Condition</div>
                    </div>

                    <div className="result-card result-card-benchmark">
                        <div className="card-title">
                            {sessionData?.device_type === 'fortinet' ? 'FortiGate' :
                                sessionData?.device_type?.startsWith('linux-') ? 'Linux' :
                                    sessionData?.device_type === 'apache' ? 'Apache' : 'Cisco'}
                        </div>
                        <div className="card-subtitle">CIS Benchmark</div>
                    </div>

                    {/* Row 2: اطلاعات */}
                    <div className="result-card result-card-info">
                        <div className="card-label">Asset</div>
                        <div className="card-value">{sessionData?.asset_name || 'N/A'}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">IP Address</div>
                        <div className="card-value">{sessionData?.target_ip || 'N/A'}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Audit Date</div>
                        <div className="card-value">
                            {sessionData?.completed_at ? new Date(sessionData.completed_at).toLocaleDateString() : 'N/A'}
                        </div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Device Type</div>
                        <div className="card-value">{sessionData?.device_type || 'N/A'}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Status</div>
                        <div className="card-value">{sessionData?.status || 'completed'}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Job Number</div>
                        <div className="card-value">Job Number {sessionData?.session_id || 1}</div>
                    </div>
                </div>

                {/* Tabs and Table */}
                <div style={{ padding: '0 40px 40px' }}>
                    {/* Tab Header */}
                    <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '20px',
                        background: 'white',
                        padding: '20px',
                        borderRadius: '8px',
                        boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
                    }}>
                        <div style={{ display: 'flex', gap: '12px' }}>
                            <button
                                onClick={() => setActiveTab('audit')}
                                style={{
                                    padding: '10px 24px',
                                    background: activeTab === 'audit' ? '#1e3a5f' : 'white',
                                    color: activeTab === 'audit' ? 'white' : '#6b7280',
                                    border: activeTab === 'audit' ? 'none' : '1px solid #e5e7eb',
                                    borderRadius: '6px',
                                    fontSize: '14px',
                                    fontWeight: '600',
                                    cursor: 'pointer'
                                }}
                            >
                                Audit result
                            </button>
                            <button
                                onClick={() => setActiveTab('unsuccessful')}
                                style={{
                                    padding: '10px 24px',
                                    background: activeTab === 'unsuccessful' ? '#1e3a5f' : 'white',
                                    color: activeTab === 'unsuccessful' ? 'white' : '#6b7280',
                                    border: activeTab === 'unsuccessful' ? 'none' : '1px solid #e5e7eb',
                                    borderRadius: '6px',
                                    fontSize: '14px',
                                    fontWeight: '600',
                                    cursor: 'pointer'
                                }}
                            >
                                Unsuccessful Section
                            </button>
                        </div>
                        <button
                            onClick={handleHardenAll}
                            disabled={failedChecks === 0}
                            style={{
                                padding: '10px 24px',
                                background: failedChecks === 0 ? '#9ca3af' : '#1e3a5f',
                                color: 'white',
                                border: 'none',
                                borderRadius: '6px',
                                fontSize: '14px',
                                fontWeight: '600',
                                cursor: failedChecks === 0 ? 'not-allowed' : 'pointer'
                            }}
                        >
                            🛡️ Harden All
                        </button>
                        {onNavigateToAuditing && (
                            <button
                                onClick={onNavigateToAuditing}
                                style={{
                                    padding: '10px 24px',
                                    background: 'white',
                                    color: '#1e3a5f',
                                    border: '2px solid #1e3a5f',
                                    borderRadius: '6px',
                                    fontSize: '14px',
                                    fontWeight: '600',
                                    cursor: 'pointer'
                                }}
                            >
                                🔍 Go to Auditing
                            </button>
                        )}

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
                                    <th>Result</th>
                                    <th style={{ width: '120px' }}>Action</th>
                                </tr>
                                </thead>
                                <tbody>
                                {displayedChecks && displayedChecks.length > 0 ? (
                                    displayedChecks.map((check) => (
                                        <tr key={check.id}>
                                            <td style={{ color: '#ef4444', fontWeight: '600' }}>{check.check_number}</td>
                                            <td>
                                                <div className="recommendation-text">{check.check_title}</div>
                                            </td>
                                            <td>{getStatusBadge(check.status)}</td>
                                            <td style={{ textAlign: 'center' }}>
                                                {check.status?.toString().toUpperCase() === 'FAIL' && (
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
                                                        🛡️ Harden
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan="4" style={{ textAlign: 'center', padding: '40px' }}>
                                            {activeTab === 'unsuccessful' ? 'No unsuccessful checks' : 'No results'}
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
                    deviceType={sessionData.device_type}
                    onClose={() => setShowHardenAllModal(false)}
                    onSuccess={handleModalSuccess}
                />
            )}

            {showFixSingleModal && selectedCheck && (
                <FixSingleModal
                    check={selectedCheck}
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

export default FixUnsuccessfulResults;