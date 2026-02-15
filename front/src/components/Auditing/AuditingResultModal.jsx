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
                .then((data) => {
                    console.log("📊 Session details:", data);
                    setSessionDetails(data);
                })
                .catch((err) => console.error("Failed to fetch session details:", err));

            // Fetch results
            dispatch(fetchAuditResults(session.session_id));
        }
    }, [isOpen, session, dispatch]);

    if (!isOpen) return null;

    // ✅ محاسبه آمار از دو منبع
    let totalChecks = 0;
    let passedChecks = 0;
    let failedChecks = 0;

    // اول: سعی کن از compliance بگیری
    if (sessionDetails?.compliance) {
        totalChecks = sessionDetails.compliance.total_checks || sessionDetails.compliance.total || 0;
        passedChecks = sessionDetails.compliance.passed_checks || sessionDetails.compliance.passed || 0;
        failedChecks = sessionDetails.compliance.failed_checks || sessionDetails.compliance.failed || 0;
        console.log("📊 از compliance:", { totalChecks, passedChecks, failedChecks });
    }

    // دوم: اگه نبود، از results محاسبه کن
    if (totalChecks === 0 && results && results.length > 0) {
        totalChecks = results.length;
        passedChecks = results.filter(r => {
            const status = r.status?.toString().toUpperCase();
            return status === 'PASS' || status === 'PASSED' || status === 'SUCCESS';
        }).length;
        failedChecks = results.filter(r => {
            const status = r.status?.toString().toUpperCase();
            return status === 'FAIL' || status === 'FAILED';
        }).length;
        console.log("📊 از results محاسبه شد:", { totalChecks, passedChecks, failedChecks });
    }

    // محاسبه درصدها
    const conformityPercent = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonConformityPercent = totalChecks > 0 ? Math.round((failedChecks / totalChecks) * 100) : 0;

    console.log("✅ آمار نهایی:", {
        totalChecks,
        passedChecks,
        failedChecks,
        conformityPercent,
        nonConformityPercent
    });

    const getResultBadge = (status) => {
        const normalizedStatus = status?.toString().toUpperCase();

        if (normalizedStatus === "PASS" || normalizedStatus === "PASSED") {
            return <span className="result-badge result-success">Successful</span>;
        } else if (normalizedStatus === "FAIL" || normalizedStatus === "FAILED") {
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

                    {/* ✅ Conformity Card با inline style */}
                    <div className="result-card result-card-success">
                        <div className="card-percent" style={{
                            fontSize: '28px',
                            fontWeight: '700',
                            color: '#059669',
                            marginBottom: '8px',
                            display: 'block',
                            lineHeight: '1.2'
                        }}>
                            {conformityPercent}% | {passedChecks}
                        </div>
                        <div className="card-label" style={{
                            fontSize: '14px',
                            color: '#6b7280',
                            fontWeight: '500',
                            display: 'block'
                        }}>
                            Conformity
                        </div>
                    </div>

                    {/* ✅ Non-Conformity Card با inline style */}
                    <div className="result-card result-card-danger">
                        <div className="card-percent" style={{
                            fontSize: '28px',
                            fontWeight: '700',
                            color: '#dc2626',
                            marginBottom: '8px',
                            display: 'block',
                            lineHeight: '1.2'
                        }}>
                            {nonConformityPercent}% | {failedChecks}
                        </div>
                        <div className="card-label" style={{
                            fontSize: '14px',
                            color: '#6b7280',
                            fontWeight: '500',
                            display: 'block'
                        }}>
                            Non-Conformity
                        </div>
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
                                        {totalChecks > 0
                                            ? `Total: ${totalChecks} checks (${passedChecks} passed, ${failedChecks} failed)`
                                            : "No results available"}
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

export default AuditingResultModal;