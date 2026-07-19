import { useEffect, useState, Fragment } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults, fetchAuditSession } from "../../store/auditSlice";
import { getDeviceName } from "../../store/hardeningSlice";
import { FixUnsuccessfulWizard } from "../Hardening/FixUnsuccessfulWizard";

const titleCase = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "-");

export const AuditingResultModal = ({ session, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { results, isLoadingResults } = useSelector((state) => state.audit);
    const [sessionDetails, setSessionDetails] = useState(session);
    const [showHardeningWizard, setShowHardeningWizard] = useState(false);
    const [expandedRows, setExpandedRows] = useState(() => new Set());

    const toggleRow = (id) =>
        setExpandedRows((prev) => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            return next;
        });

    useEffect(() => {
        if (isOpen && session) {
            const sessionId = parseInt(session.session_id);

            if (isNaN(sessionId)) {
                return;
            }

            dispatch(fetchAuditSession(sessionId))
                .unwrap()
                .then((data) => {
                    setSessionDetails(data);
                })
                .catch((err) => console.error("Failed to fetch session details:", err));

            dispatch(fetchAuditResults(sessionId));
        }
    }, [isOpen, session, dispatch]);

    if (!isOpen) return null;

    let totalChecks = 0;
    let passedChecks = 0;
    let failedChecks = 0;

    if (sessionDetails?.compliance) {
        totalChecks = sessionDetails.compliance.total_checks || sessionDetails.compliance.total || 0;
        passedChecks = sessionDetails.compliance.passed_checks || sessionDetails.compliance.passed || 0;
        failedChecks = sessionDetails.compliance.failed_checks || sessionDetails.compliance.failed || 0;
    }

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
    }

    const conformityPercent = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonConformityPercent = totalChecks > 0 ? Math.round((failedChecks / totalChecks) * 100) : 0;
    const otherChecks = Math.max(totalChecks - passedChecks - failedChecks, 0);

    // FortiGate multi-VDOM audits tag each result with its VDOM ("global"/"root"/<name>).
    // Only show the VDOM column when at least one result carries it.
    const hasVdom = Array.isArray(results) && results.some((r) => r.vdom);
    // Columns: Section [+ VDOM] + Recommendation + Result + Details.
    const colCount = hasVdom ? 5 : 4;

    const getResultBadge = (status) => {
        const normalizedStatus = status?.toString().toUpperCase();

        if (normalizedStatus === "PASS" || normalizedStatus === "PASSED") {
            return <span className="result-badge result-success">Successful</span>;
        } else if (normalizedStatus === "FAIL" || normalizedStatus === "FAILED") {
            return <span className="result-badge result-fail">Failed</span>;
        } else if (normalizedStatus === "RUNNING") {
            return <span className="result-badge result-running">Running</span>;
        } else if (normalizedStatus === "ERROR") {
            return <span className="result-badge result-error">Error</span>;
        } else {
            return <span className="result-badge result-unknown">{titleCase(status) === "-" ? "Unknown" : titleCase(status)}</span>;
        }
    };

    return (
        <>
        <div className="modal-overlay result-modal-overlay" onClick={onClose}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Audit Result
                    </button>
                </div>

                {/* Statistics Cards — device info row, then summary row */}
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
                        <div className="card-value">
                            {sessionDetails?.device_type
                                ? getDeviceName(sessionDetails.sub_device_type || sessionDetails.device_type)
                                : "-"}
                        </div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Status</div>
                        <div className="card-value">{titleCase(sessionDetails?.status)}</div>
                    </div>
                </div>

                <div className="result-stats-summary">
                    <div className="result-card result-card-success">
                        <div className="card-percent">{conformityPercent}%</div>
                        <div className="card-sub">{passedChecks} of {totalChecks} checks</div>
                        <div className="card-label">Conformity</div>
                    </div>

                    <div className="result-card result-card-danger">
                        <div className="card-percent">{nonConformityPercent}%</div>
                        <div className="card-sub">{failedChecks} of {totalChecks} checks</div>
                        <div className="card-label">Non-Conformity</div>
                    </div>

                    <div className="result-card result-card-total">
                        <div className="card-number">{totalChecks}</div>
                        <div className="card-label">
                            Total Conditions
                            {otherChecks > 0 && (
                                <span style={{ display: 'block', fontSize: '12px', color: '#9ca3af', marginTop: '4px' }}>
                                    ({otherChecks} error / other)
                                </span>
                            )}
                        </div>
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
                                {hasVdom && <th>VDOM</th>}
                                <th>Recommendation</th>
                                <th>Result</th>
                                <th>Details</th>
                            </tr>
                            </thead>
                            <tbody>
                            {results && results.length > 0 ? (
                                results.map((result) => {
                                    const hasEvidence = !!result.evidence_snippet;
                                    const isExpanded = expandedRows.has(result.id);
                                    return (
                                        <Fragment key={result.id}>
                                            <tr>
                                                <td>{result.check_number}</td>
                                                {hasVdom && (
                                                    <td>
                                                        {result.vdom && result.vdom !== "global"
                                                            ? <span className="vdom-chip">{result.vdom}</span>
                                                            : <span style={{ color: "#6b7280" }}>{result.vdom || "—"}</span>}
                                                    </td>
                                                )}
                                                <td>
                                                    <div className="recommendation-text">
                                                        {result.check_title}
                                                    </div>
                                                </td>
                                                <td>
                                                    {getResultBadge(result.status)}
                                                    {result.needs_review && (
                                                        <span
                                                            title="Heuristic check — this PASS/FAIL is indicative only and must be verified manually."
                                                            style={{
                                                                display: "inline-block",
                                                                marginTop: "4px",
                                                                padding: "2px 8px",
                                                                borderRadius: "10px",
                                                                fontSize: "11px",
                                                                fontWeight: 600,
                                                                background: "#fef3c7",
                                                                color: "#92400e",
                                                                border: "1px solid #fcd34d",
                                                                whiteSpace: "nowrap",
                                                            }}
                                                        >
                                                            ⚠ Manual review
                                                        </span>
                                                    )}
                                                </td>
                                                <td>
                                                    {hasEvidence ? (
                                                        <button
                                                            type="button"
                                                            className="btn-evidence-toggle"
                                                            onClick={() => toggleRow(result.id)}
                                                            aria-expanded={isExpanded}
                                                            style={{
                                                                background: "transparent",
                                                                border: "1px solid #d1d5db",
                                                                borderRadius: "6px",
                                                                padding: "4px 10px",
                                                                fontSize: "12px",
                                                                cursor: "pointer",
                                                                color: "#374151",
                                                                whiteSpace: "nowrap",
                                                            }}
                                                        >
                                                            {isExpanded ? "▼ Hide" : "▶ Details"}
                                                        </button>
                                                    ) : (
                                                        <span style={{ color: "#9ca3af" }}>—</span>
                                                    )}
                                                </td>
                                            </tr>
                                            {hasEvidence && isExpanded && (
                                                <tr className="evidence-row">
                                                    <td colSpan={colCount} style={{ background: "#f9fafb", padding: "12px 16px" }}>
                                                        <div style={{
                                                            fontSize: "12px",
                                                            fontWeight: 600,
                                                            color: "#6b7280",
                                                            textTransform: "uppercase",
                                                            letterSpacing: "0.04em",
                                                            marginBottom: "6px",
                                                        }}>
                                                            Evidence / Remediation
                                                        </div>
                                                        <pre style={{
                                                            margin: 0,
                                                            whiteSpace: "pre-wrap",
                                                            wordBreak: "break-word",
                                                            fontFamily: "monospace",
                                                            fontSize: "12px",
                                                            lineHeight: 1.5,
                                                            color: "#111827",
                                                            background: "#ffffff",
                                                            border: "1px solid #e5e7eb",
                                                            borderRadius: "6px",
                                                            padding: "10px 12px",
                                                            maxHeight: "360px",
                                                            overflow: "auto",
                                                        }}>
                                                            {result.evidence_snippet}
                                                        </pre>
                                                    </td>
                                                </tr>
                                            )}
                                        </Fragment>
                                    );
                                })
                            ) : (
                                <tr>
                                    <td colSpan={colCount} style={{ textAlign: "center", padding: "40px" }}>
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

        <FixUnsuccessfulWizard
            isOpen={showHardeningWizard}
            onClose={() => setShowHardeningWizard(false)}
            onNavigateToAuditing={onClose}
            preselectedSessionId={sessionDetails?.session_id ? parseInt(sessionDetails.session_id) : undefined}
            preselectedDeviceType={sessionDetails?.device_type}
        />
        </>
    );
};

export default AuditingResultModal;
