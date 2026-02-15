import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults } from "../../store/hardeningSlice";
import HardenAllModal from './HardenAllModal';
import FixSingleModal from './FixSingleModal';

export const FixUnsuccessfulResults = ({ sessionData }) => {
    const dispatch = useDispatch();
    const { cisChecks, isLoading } = useSelector((state) => state.hardening);
    const [showHardenAllModal, setShowHardenAllModal] = useState(false);
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState(null);
    const [activeTab, setActiveTab] = useState('audit'); // 'audit' or 'unsuccessful'

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
        // Refresh results after successful hardening
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
        // Refresh results after successful fix
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
        // Normalize status to uppercase for consistent comparison
        const normalizedStatus = status?.toString().toUpperCase();

        if (normalizedStatus === "PASS") {
            return <span className="hardening-status-badge hardening-status-success">successful</span>;
        } else if (normalizedStatus === "FAIL") {
            return <span className="hardening-status-badge hardening-status-fail">Unsuccessful</span>;
        } else {
            return <span className="hardening-status-badge hardening-status-unknown">unknown</span>;
        }
    };

    // Count statistics
    const totalChecks = cisChecks?.length || 0;
    const passedChecks = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'PASS').length || 0;
    const failedChecks = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL').length || 0;
    const compliancePercentage = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;

    // Filter checks based on active tab
    const displayedChecks = activeTab === 'unsuccessful'
        ? cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL')
        : cisChecks;

    return (
        <div className="hardening-results-container">
            {/* Summary Cards */}
            <div className="hardening-summary-cards">
                <div className="hardening-summary-card hardening-card-success">
                    <div className="hardening-card-value">{compliancePercentage}% | {passedChecks}</div>
                    <div className="hardening-card-label">Conformity</div>
                </div>

                <div className="hardening-summary-card hardening-card-danger">
                    <div className="hardening-card-value">{100 - compliancePercentage}% | {failedChecks}</div>
                    <div className="hardening-card-label">Non-Conformity</div>
                </div>

                <div className="hardening-summary-card">
                    <div className="hardening-card-value">{totalChecks}</div>
                    <div className="hardening-card-label">Total Condition</div>
                </div>

                <div className="hardening-summary-card">
                    <div className="hardening-card-value">{sessionData?.device_type || 'N/A'}</div>
                    <div className="hardening-card-label">Device Type</div>
                </div>
            </div>

            {/* Session Info */}
            <div className="hardening-session-details">
                <div className="hardening-detail-item">
                    <span className="hardening-detail-label">Asset</span>
                    <span className="hardening-detail-value">{sessionData?.asset_name || 'N/A'}</span>
                </div>
                <div className="hardening-detail-item">
                    <span className="hardening-detail-label">IP Address</span>
                    <span className="hardening-detail-value">{sessionData?.target_ip || 'N/A'}</span>
                </div>
                <div className="hardening-detail-item">
                    <span className="hardening-detail-label">Audit Date</span>
                    <span className="hardening-detail-value">
                        {sessionData?.completed_at ? new Date(sessionData.completed_at).toLocaleString() : 'N/A'}
                    </span>
                </div>
                <div className="hardening-detail-item">
                    <span className="hardening-detail-label">Device Type</span>
                    <span className="hardening-detail-value">{sessionData?.device_type || 'N/A'}</span>
                </div>
                <div className="hardening-detail-item">
                    <span className="hardening-detail-label">Status</span>
                    <span className="hardening-detail-value">{sessionData?.status || 'successful'}</span>
                </div>
                <div className="hardening-detail-item">
                    <span className="hardening-detail-label">Job Number</span>
                    <span className="hardening-detail-value">Job Number {sessionData?.session_id || 1}</span>
                </div>
            </div>

            {/* Tabs and Table */}
            <div className="hardening-results-table-section">
                {/* Tab Header with Harden All Button */}
                <div className="hardening-tabs-header">
                    <div className="hardening-tabs">
                        <button
                            className={`hardening-tab ${activeTab === 'audit' ? 'active' : ''}`}
                            onClick={() => setActiveTab('audit')}
                        >
                            Audit result
                        </button>
                        <button
                            className={`hardening-tab ${activeTab === 'unsuccessful' ? 'active' : ''}`}
                            onClick={() => setActiveTab('unsuccessful')}
                        >
                            Unsuccessful Section
                        </button>
                    </div>
                    <button
                        className="hardening-btn-harden-all"
                        onClick={handleHardenAll}
                        disabled={failedChecks === 0 || isLoading}
                        title={failedChecks === 0 ? "No failed checks to harden" : `Harden ${failedChecks} failed checks`}
                    >
                        🛡️ Harden All
                    </button>
                </div>

                {/* Table */}
                <div className="hardening-results-table-wrapper">
                    {isLoading ? (
                        <div className="hardening-loading-spinner">Loading results...</div>
                    ) : (
                        <table className="hardening-results-table">
                            <thead>
                            <tr>
                                <th>Section</th>
                                <th>Recommendation</th>
                                <th>Result</th>
                                {activeTab === 'unsuccessful' && <th>Action</th>}
                            </tr>
                            </thead>
                            <tbody>
                            {displayedChecks && displayedChecks.length > 0 ? (
                                displayedChecks.map((check) => (
                                    <tr key={check.id}>
                                        <td>{check.check_number}</td>
                                        <td>
                                            <div className="hardening-recommendation-text">
                                                {check.check_title}
                                            </div>
                                        </td>
                                        <td>{getStatusBadge(check.status)}</td>
                                        {activeTab === 'unsuccessful' && (
                                            <td>
                                                {check.status?.toString().toUpperCase() === 'FAIL' && (
                                                    <button
                                                        className="hardening-btn-harden-single"
                                                        onClick={() => handleHardenSingle(check)}
                                                        title={`Fix check ${check.check_number}`}
                                                    >
                                                        🛡️ Harden
                                                    </button>
                                                )}
                                            </td>
                                        )}
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td
                                        colSpan={activeTab === 'unsuccessful' ? "4" : "3"}
                                        style={{ textAlign: "center", padding: "40px" }}
                                    >
                                        {activeTab === 'unsuccessful'
                                            ? "No unsuccessful checks found"
                                            : "No results available"}
                                    </td>
                                </tr>
                            )}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>

            {/* Harden All Modal */}
            {showHardenAllModal && (
                <HardenAllModal
                    sessionId={sessionData.session_id}
                    deviceType={sessionData.device_type}
                    onClose={() => setShowHardenAllModal(false)}
                    onSuccess={handleModalSuccess}
                />
            )}

            {/* Fix Single Modal */}
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