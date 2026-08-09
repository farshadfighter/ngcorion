import { useEffect, useState, Fragment } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults, fetchAuditSession } from "../../store/auditSlice";
import { getDeviceName } from "../../store/hardeningSlice";
import { FixUnsuccessfulWizard } from "../Hardening/FixUnsuccessfulWizard";
import { ResultHardeningBar } from "./ResultHardeningBar";

const titleCase = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "-");

// ── Windows CIS scope map (static benchmark data) ─────────────────────────────
// Sections that only apply to Domain Controllers vs Member Servers. Audits are
// already role-filtered server-side; these drive the per-row DC / MS badges.
const WIN_DC_SECTIONS = new Set([
    "2.2.2", "2.2.7", "2.2.9", "2.2.18", "2.2.21", "2.2.26", "2.2.28", "2.2.32",
    "2.2.37", "2.2.38", "2.2.48",
    "2.3.5.1", "2.3.5.2", "2.3.5.3", "2.3.5.4", "2.3.5.6", "2.3.10.6", "2.3.11.13",
    "17.1.2", "17.1.3", "17.2.2", "17.2.3", "17.2.4", "17.4.1", "17.4.2",
]);
const WIN_MS_SECTIONS = new Set([
    "1.2.3",
    "2.2.3", "2.2.8", "2.2.10", "2.2.19", "2.2.22", "2.2.27", "2.2.29", "2.2.33", "2.2.39",
    "2.3.1.1", "2.3.7.6", "2.3.7.8", "2.3.9.5", "2.3.10.2", "2.3.10.3", "2.3.10.7", "2.3.10.11",
    "18.4.1",
]);

const isWindowsDevice = (dt) => (dt || "").toLowerCase().startsWith("windows");

// Returns "DC" | "MS" | null for a Windows check number (e.g. "WIN-2025-2.2.2").
const winScope = (checkNumber) => {
    if (!checkNumber || !checkNumber.startsWith("WIN-")) return null;
    const section = checkNumber.replace(/^WIN-\d+-/, "");
    if (WIN_DC_SECTIONS.has(section)) return "DC";
    if (WIN_MS_SECTIONS.has(section)) return "MS";
    return null;
};

// A check is "manual" (no automated fix) when it is NOT_APPLICABLE/SKIPPED, or a
// Windows Section 19 (per-user / HKU) control.
const isManualCheck = (result) => {
    const status = result?.status?.toString().toUpperCase();
    if (status === "NOT_APPLICABLE" || status === "SKIPPED") return true;
    return /^WIN-\d+-19\./.test(result?.check_number || "");
};

const scopeBadgeStyle = (scope) => ({
    display: "inline-block",
    marginLeft: "6px",
    padding: "1px 7px",
    borderRadius: "10px",
    fontSize: "10px",
    fontWeight: 700,
    verticalAlign: "middle",
    background: scope === "DC" ? "#e0e7ff" : "#dcfce7",
    color: scope === "DC" ? "#3730a3" : "#166534",
    border: `1px solid ${scope === "DC" ? "#c7d2fe" : "#bbf7d0"}`,
});

const manualBadgeStyle = {
    display: "inline-block",
    marginLeft: "6px",
    padding: "1px 7px",
    borderRadius: "10px",
    fontSize: "10px",
    fontWeight: 700,
    verticalAlign: "middle",
    background: "#f3f4f6",
    color: "#6b7280",
    border: "1px solid #e5e7eb",
};

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

    // The modal covers the whole viewport, so the page behind it must not
    // scroll — otherwise its scrollbar shows up alongside the modal's own.
    useEffect(() => {
        if (!isOpen) return undefined;
        const previous = document.body.style.overflow;
        document.body.style.overflow = "hidden";
        return () => {
            document.body.style.overflow = previous;
        };
    }, [isOpen]);

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

    // Windows: show a Server Role indicator + per-row DC/MS badges. Role is
    // inferred from which scoped checks the (already role-filtered) audit ran.
    const isWindowsSession = isWindowsDevice(sessionDetails?.device_type);
    let serverRole = null;
    if (isWindowsSession && Array.isArray(results)) {
        const scopes = new Set(results.map((r) => winScope(r.check_number)).filter(Boolean));
        if (scopes.has("DC")) serverRole = "Domain Controller";
        else if (scopes.has("MS")) serverRole = "Member Server";
    }

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

                {/* Statistics — one white panel holding the coloured summary row
                    (ordered first via CSS) above the device info row. */}
                <div className="result-stats-panel">
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

                    {isWindowsSession && serverRole && (
                        <div className="result-card result-card-info">
                            <div className="card-label">Server Role</div>
                            <div className="card-value">
                                <span
                                    style={{
                                        display: "inline-block",
                                        padding: "2px 10px",
                                        borderRadius: "10px",
                                        fontSize: "12px",
                                        fontWeight: 700,
                                        background: serverRole === "Domain Controller" ? "#e0e7ff" : "#dcfce7",
                                        color: serverRole === "Domain Controller" ? "#3730a3" : "#166534",
                                    }}
                                >
                                    {serverRole}
                                </span>
                            </div>
                        </div>
                    )}
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
                </div>

                <ResultHardeningBar
                    onHarden={() => setShowHardeningWizard(true)}
                    disabled={failedChecks === 0}
                />

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
                                                <td>
                                                    {result.check_number}
                                                    {isWindowsSession && winScope(result.check_number) && (
                                                        <span style={scopeBadgeStyle(winScope(result.check_number))}>
                                                            {winScope(result.check_number)}
                                                        </span>
                                                    )}
                                                    {isWindowsSession && isManualCheck(result) && (
                                                        <span style={manualBadgeStyle} title="Manual control — no automated fix (per-user / GPO-only).">
                                                            Manual
                                                        </span>
                                                    )}
                                                </td>
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
