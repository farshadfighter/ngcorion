import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults, fetchFortinetTemplatedChecks } from "../../store/hardeningSlice";
import HardenAllModal from './HardenAllModal';
import FixSingleModal from './FixSingleModal';
import ViewFixModal from './ViewFixModal';

export const FixUnsuccessfulResults = ({ sessionData, onClose, onNavigateToAuditing }) => {
    const dispatch = useDispatch();
    const { cisChecks, isLoading, fortinetTemplatedChecks } = useSelector((state) => state.hardening);
    const [showHardenAllModal, setShowHardenAllModal] = useState(false);
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState(null);
    const [viewFixCheck, setViewFixCheck] = useState(null);
    const [activeTab, setActiveTab] = useState('audit');

    const isFortinet = sessionData?.device_type === 'fortinet';

    useEffect(() => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
    }, [sessionData?.session_id, sessionData?.device_type, dispatch]);

    // FortiGate: load which checks are auto-fixable so we can show a "Manual"
    // badge (instead of a dead-end "Harden" button) for review-only checks.
    useEffect(() => {
        if (isFortinet) dispatch(fetchFortinetTemplatedChecks());
    }, [isFortinet, dispatch]);

    // A check is auto-fixable when it's not a FortiGate device, or the templated
    // list hasn't loaded (fail open — never hide "Harden" by mistake), or the
    // check number is in the templated set.
    const templatedSet = new Set(fortinetTemplatedChecks || []);
    const isAutoFixable = (check) =>
        !isFortinet || templatedSet.size === 0 || templatedSet.has(check.check_number);

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

    const handleViewFix = (check) => setViewFixCheck(check);

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

    const chipStyle = {
        display: 'inline-block',
        marginTop: '4px',
        padding: '2px 8px',
        borderRadius: '10px',
        fontSize: '11px',
        fontWeight: 600,
        whiteSpace: 'nowrap',
    };

    const getStatusBadge = (check) => {
        const s = check.status?.toString().toUpperCase();
        const base =
            s === 'PASS' ? <span className="result-badge result-success">successful</span>
            : s === 'FAIL' ? <span className="result-badge result-fail">Unsuccessful</span>
            : <span className="result-badge result-unknown">unknown</span>;
        // Live feedback from this session's hardening (set by markCheckHardened —
        // no reload / re-audit needed to see it).
        const vdomSuffix = check.hardenedVdom ? ` (VDOM: ${check.hardenedVdom})` : '';
        return (
            <>
                {base}
                {check.justHardened && (
                    <span style={{ ...chipStyle, display: 'block', background: '#dcfce7', color: '#166534', border: '1px solid #86efac' }}
                          title={`Fixed and verified in this session${vdomSuffix}`}>
                        ✓ Hardened{vdomSuffix}
                    </span>
                )}
                {check.manualApplied && !check.justHardened && (
                    <span style={{ ...chipStyle, display: 'block', background: '#fef3c7', color: '#92400e', border: '1px solid #fcd34d' }}
                          title={`Remediation pushed to the device${vdomSuffix}; manual checks are not auto-verified`}>
                        🛠 Applied — re-audit to verify{vdomSuffix}
                    </span>
                )}
            </>
        );
    };

    const getDeviceLabel = (dt) => {
        if (dt === 'fortinet')          return 'FortiGate';
        if (dt === 'linux' || dt?.startsWith('linux-')) return 'Linux';
        if (dt === 'apache')            return 'Apache';
        if (dt === 'mongodb')           return 'MongoDB';
        if (dt?.startsWith('mssql-'))   return 'SQL Server';
        if (dt?.startsWith('windows-')) return 'Windows';
        return 'Cisco';
    };

    const totalChecks   = cisChecks?.length || 0;
    const passedChecks  = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'PASS').length || 0;
    const failedChecks  = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL').length || 0;
    const compliancePercentage    = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonCompliancePercentage = totalChecks > 0 ? Math.round((failedChecks / totalChecks) * 100) : 0;

    const displayedChecks = activeTab === 'unsuccessful'
        ? cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL')
        : cisChecks;

    return (
        <div className="modal-overlay result-modal-overlay" onClick={!showFixSingleModal && !showHardenAllModal ? onClose : undefined}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Hardening Result
                    </button>
                </div>

                {/* Statistics Cards */}
                <div className="result-stats-container">
                    <div className="result-card result-card-success" style={{ background: 'linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%)', border: '2px solid #6ee7b7' }}>
                        <div className="card-percent" style={{ fontSize: '32px', fontWeight: '700', color: '#059669', marginBottom: '8px' }}>
                            {compliancePercentage}% | {passedChecks}
                        </div>
                        <div className="card-label">Conformity</div>
                    </div>

                    <div className="result-card result-card-danger" style={{ background: 'linear-gradient(135deg, #fee2e2 0%, #fecaca 100%)', border: '2px solid #fca5a5' }}>
                        <div className="card-percent" style={{ fontSize: '32px', fontWeight: '700', color: '#dc2626', marginBottom: '8px' }}>
                            {nonCompliancePercentage}% | {failedChecks}
                        </div>
                        <div className="card-label">Non-Conformity</div>
                    </div>

                    <div className="result-card result-card-total">
                        <div className="card-number">{totalChecks}</div>
                        <div className="card-label">Total Condition</div>
                    </div>

                    {/* ← fix: همه 19 device type */}
                    <div className="result-card result-card-benchmark">
                        <div className="card-title">{getDeviceLabel(sessionData?.sub_device_type || sessionData?.device_type)}</div>
                    </div>

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
                <div style={{ padding: '0 24px 24px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', background: 'white', padding: '16px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
                        <div style={{ display: 'flex', gap: '12px' }}>
                            <button
                                onClick={() => setActiveTab('audit')}
                                style={{ padding: '10px 24px', background: activeTab === 'audit' ? '#1e3a5f' : 'white', color: activeTab === 'audit' ? 'white' : '#6b7280', border: activeTab === 'audit' ? 'none' : '1px solid #e5e7eb', borderRadius: '6px', fontSize: '14px', fontWeight: '600', cursor: 'pointer' }}
                            >
                                Audit result
                            </button>
                            <button
                                onClick={() => setActiveTab('unsuccessful')}
                                style={{ padding: '10px 24px', background: activeTab === 'unsuccessful' ? '#1e3a5f' : 'white', color: activeTab === 'unsuccessful' ? 'white' : '#6b7280', border: activeTab === 'unsuccessful' ? 'none' : '1px solid #e5e7eb', borderRadius: '6px', fontSize: '14px', fontWeight: '600', cursor: 'pointer' }}
                            >
                                Unsuccessful Section
                            </button>
                        </div>
                        <button
                            onClick={handleHardenAll}
                            disabled={failedChecks === 0}
                            style={{ padding: '10px 24px', background: failedChecks === 0 ? '#9ca3af' : '#1e3a5f', color: 'white', border: 'none', borderRadius: '6px', fontSize: '14px', fontWeight: '600', cursor: failedChecks === 0 ? 'not-allowed' : 'pointer' }}
                        >
                            🛡️ Harden All
                        </button>
                        {onNavigateToAuditing && (
                            <button
                                onClick={onNavigateToAuditing}
                                style={{ padding: '10px 24px', background: 'white', color: '#1e3a5f', border: '2px solid #1e3a5f', borderRadius: '6px', fontSize: '14px', fontWeight: '600', cursor: 'pointer' }}
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
                                            <td>{getStatusBadge(check)}</td>
                                            <td style={{ textAlign: 'center' }}>
                                                {check.status?.toString().toUpperCase() === 'FAIL' && (
                                                    isAutoFixable(check) ? (
                                                        <button
                                                            onClick={() => handleHardenSingle(check)}
                                                            style={{ padding: '8px 18px', background: '#1e3a5f', color: 'white', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: '600', cursor: 'pointer' }}
                                                        >
                                                            🛡️ Harden
                                                        </button>
                                                    ) : (
                                                        <button
                                                            onClick={() => handleViewFix(check)}
                                                            title="No automated fix — view the manual remediation commands"
                                                            style={{ padding: '8px 16px', background: 'white', color: '#1e3a5f', border: '2px solid #1e3a5f', borderRadius: '6px', fontSize: '13px', fontWeight: '600', cursor: 'pointer' }}
                                                        >
                                                            📋 View Fix
                                                        </button>
                                                    )
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

            {viewFixCheck && (
                <ViewFixModal
                    checkId={viewFixCheck.check_number}
                    checkTitle={viewFixCheck.check_title}
                    resultId={viewFixCheck.id}
                    assetId={sessionData?.asset_id}
                    onClose={() => setViewFixCheck(null)}
                    onSuccess={handleModalSuccess}
                />
            )}
        </div>
    );
};

export default FixUnsuccessfulResults;