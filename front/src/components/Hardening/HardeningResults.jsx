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
        // Use callback if provided, otherwise fallback to hash navigation
        if (onNavigateToAuditing) {
            onNavigateToAuditing();
        } else {
            // Fallback: Navigate to operation-device section
            window.location.hash = "#operation-device";
        }
    };

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
        const normalizedStatus = status?.toString().toUpperCase();

        if (normalizedStatus === "PASS") {
            return <span className="hardening-status-badge hardening-status-success">Pass</span>;
        } else if (normalizedStatus === "FAIL") {
            return <span className="hardening-status-badge hardening-status-fail">Fail</span>;
        } else {
            return <span className="hardening-status-badge hardening-status-unknown">unknown</span>;
        }
    };

    // Count failed checks for Harden All button
    const failedChecksCount = cisChecks?.filter(
        check => check.status?.toString().toUpperCase() === 'FAIL'
    ).length || 0;

    return (
        <div className="hardening-results-container">
            {/* Warning Box */}
            <div className="hardening-results-warning-box">
                <div className="hardening-warning-icon">ℹ️</div>
                <div className="hardening-warning-text">
                    Status of CIS Benchmark section is unknown, audit your asset to specify
                    status
                </div>
                <button className="hardening-btn-auditing" onClick={handleAuditingClick}>
                    🔍 Auditing
                </button>
            </div>

            {/* CIS Benchmark Table */}
            <div className="hardening-results-table-section">
                <div className="hardening-results-table-header">
                    <h3>{sessionData?.device_type || 'Device'} CIS Benchmark</h3>
                    <button
                        className="hardening-btn-harden-all"
                        onClick={handleHardenAll}
                        disabled={failedChecksCount === 0 || isLoading}
                        title={failedChecksCount === 0 ? "No failed checks to harden" : `Harden ${failedChecksCount} failed checks`}
                    >
                        🛡️ Harden All {failedChecksCount > 0 && `(${failedChecksCount})`}
                    </button>
                </div>

                <div className="hardening-results-table-wrapper">
                    {isLoading ? (
                        <div className="hardening-loading-spinner">Loading results...</div>
                    ) : (
                        <table className="hardening-results-table">
                            <thead>
                            <tr>
                                <th>Section</th>
                                <th>Recommendation</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                            </thead>
                            <tbody>
                            {cisChecks && cisChecks.length > 0 ? (
                                cisChecks.map((check) => (
                                    <tr key={check.id}>
                                        <td>{check.check_number}</td>
                                        <td>
                                            <div className="hardening-recommendation-text">
                                                {check.check_title}
                                            </div>
                                        </td>
                                        <td>{getStatusBadge(check.status)}</td>
                                        <td>
                                            {check.status?.toString().toUpperCase() === 'FAIL' ? (
                                                <button
                                                    className="hardening-btn-harden-single"
                                                    onClick={() => handleHardenSingle(check)}
                                                    title={`Fix check ${check.check_number}`}
                                                >
                                                    🛡️ Harden
                                                </button>
                                            ) : (
                                                <span style={{ color: '#999', fontSize: '14px' }}>—</span>
                                            )}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td
                                        colSpan="4"
                                        style={{ textAlign: "center", padding: "40px" }}
                                    >
                                        No results available
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

export default HardeningResults;