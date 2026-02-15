import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults, fetchAuditSession } from "../../store/auditSlice";

export const AuditingResultModal = ({ session, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { results, isLoadingResults } = useSelector((state) => state.audit);
    const [sessionDetails, setSessionDetails] = useState(session);

    useEffect(() => {
        if (isOpen && session) {
            // Fetch fresh session details
            dispatch(fetchAuditSession(session.session_id))
                .unwrap()
                .then((data) => setSessionDetails(data))
                .catch((err) => console.error("Failed to fetch session details:", err));

            // Fetch results
            dispatch(fetchAuditResults(session.session_id));
        }
    }, [isOpen, session, dispatch]);

    if (!isOpen) return null;

    // Calculate statistics
    const compliance = sessionDetails?.compliance || {};
    const totalChecks = compliance.total_checks || 0;
    const passedChecks = compliance.passed_checks || 0;
    const failedChecks = compliance.failed_checks || 0;
    const conformityPercent = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonConformityPercent = totalChecks > 0 ? Math.round((failedChecks / totalChecks) * 100) : 0;

    const getResultBadge = (status) => {
        // Normalize status to uppercase for consistent comparison
        const normalizedStatus = status?.toString().toUpperCase();

        if (normalizedStatus === "PASS") {
            return <span className="result-badge result-success">Successful</span>;
        } else if (normalizedStatus === "FAIL") {
            return <span className="result-badge result-fail">Failed</span>;
        } else if (normalizedStatus === "RUNNING") {
            return <span className="result-badge result-running">Running</span>;
        } else {
            return <span className="result-badge result-unknown">{status || "Unknown"}</span>;
        }
    };

    return (
        <div className="modal-overlay result-modal-overlay" onClick={onClose}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Audit Result
                    </button>
                </div>

                {/* Statistics Cards */}
                <div className="result-stats-container">
                    <div className="result-card result-card-info">
                        <div className="card-label">Asset</div>
                        <div className="card-value">{sessionDetails?.asset_name || "-"}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">IP Address</div>
                        <div className="card-value">{sessionDetails?.target_ip || "-"}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Audit Date</div>
                        <div className="card-value">
                            {sessionDetails?.started_at
                                ? new Date(sessionDetails.started_at).toLocaleDateString()
                                : "-"}
                        </div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Device Type</div>
                        <div className="card-value">{sessionDetails?.device_type || "cisco"}</div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Status</div>
                        <div className="card-value">{sessionDetails?.status || "-"}</div>
                    </div>

                    <div className="result-card result-card-success">
                        <div className="card-percent">{conformityPercent}% | {passedChecks}</div>
                        <div className="card-label">Conformity</div>
                    </div>

                    <div className="result-card result-card-danger">
                        <div className="card-percent">{nonConformityPercent}% | {failedChecks}</div>
                        <div className="card-label">Non-Conformity</div>
                    </div>

                    <div className="result-card result-card-total">
                        <div className="card-number">{totalChecks}</div>
                        <div className="card-label">Total Condition</div>
                    </div>

                    <div className="result-card result-card-benchmark">
                        <div className="card-title">{sessionDetails?.device_type === "fortinet" ? "FortiGate" : "Cisco"}</div>
                        <div className="card-subtitle">CIS Benchmark</div>
                    </div>
                </div>

                {/* Results Table */}
                <div className="result-table-wrapper">
                    {isLoadingResults ? (
                        <div className="loading-spinner">Loading results...</div>
                    ) : (
                        <table className="result-table">
                            <thead>
                            <tr>
                                <th>Section</th>
                                <th>Recommendation</th>
                                <th>Result</th>
                            </tr>
                            </thead>
                            <tbody>
                            {results && results.length > 0 ? (
                                results.map((result) => (
                                    <tr key={result.id}>
                                        <td>{result.check_number}</td>
                                        <td>
                                            <div className="recommendation-text">
                                                {result.check_title}
                                            </div>
                                        </td>
                                        <td>{getResultBadge(result.status)}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="3" style={{ textAlign: "center", padding: "40px" }}>
                                        No results available
                                    </td>
                                </tr>
                            )}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>
        </div>
    );
};