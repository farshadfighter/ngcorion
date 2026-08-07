import React from "react";

/**
 * "Audit Summary": the label/value rows from the Figma mock (614x72 each, laid
 * out two per line). Every value comes from the risk detail payload.
 */
const buildRows = (score, auditSummary) => [
    ["Audit Scan", auditSummary?.audit_session_id ?? "-"],
    ["Total Applicable Controls", auditSummary?.total_applicable ?? "-"],
    ["Passed Controls", auditSummary?.passed ?? "-"],
    ["Active Failed Controls", auditSummary?.active_failed ?? score?.active_audit_findings_count ?? "-"],
    [
        "Fixed by Hardening",
        auditSummary?.resolved_by_hardening ?? score?.resolved_by_hardening_count ?? "-",
    ],
    ["Critical Findings", score?.critical_findings_count ?? "-"],
    ["High Findings", score?.high_findings_count ?? "-"],
    ["Medium Findings", score?.medium_findings_count ?? "-"],
    ["Low Findings", score?.low_findings_count ?? "-"],
    ["Weighted Failed Score", score?.audit_failed_weight ?? "-"],
    ["Weighted Applicable Score", score?.audit_applicable_weight ?? "-"],
    ["Audit Risk Score", score?.audit_risk_score ?? "-"],
];

export const AuditSummary = ({ score, auditSummary }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">Audit Summary</h3>
        <div className="ard-summary-grid">
            {buildRows(score, auditSummary).map(([label, value]) => (
                <div className="ard-summary-row" key={label}>
                    <span className="ard-summary-label">{label}</span>
                    <span className="ard-summary-value">{value}</span>
                </div>
            ))}
        </div>
    </section>
);

export default AuditSummary;
