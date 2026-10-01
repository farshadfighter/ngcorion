import React from "react";
import { t, n } from "../../../i18n";

/**
 * "Audit Summary": the label/value rows from the Figma mock (614x72 each, laid
 * out two per line). Every value comes from the risk detail payload.
 */
const buildRows = (score, auditSummary) => [
    [t("Audit Scan"), auditSummary?.audit_session_id ?? "-"],
    [t("Total Applicable Controls"), auditSummary?.total_applicable ?? "-"],
    [t("Passed Controls"), auditSummary?.passed ?? "-"],
    [t("Active Failed Controls"), auditSummary?.active_failed ?? score?.active_audit_findings_count ?? "-"],
    [
        t("Fixed by Hardening"),
        auditSummary?.resolved_by_hardening ?? score?.resolved_by_hardening_count ?? "-",
    ],
    [t("Critical Findings"), score?.critical_findings_count ?? "-"],
    [t("High Findings"), score?.high_findings_count ?? "-"],
    [t("Medium Findings"), score?.medium_findings_count ?? "-"],
    [t("Low Findings"), score?.low_findings_count ?? "-"],
    [t("Weighted Failed Score"), score?.audit_failed_weight ?? "-"],
    [t("Weighted Applicable Score"), score?.audit_applicable_weight ?? "-"],
    [t("Audit Risk Score"), score?.audit_risk_score ?? "-"],
];

export const AuditSummary = ({ score, auditSummary }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">{t("Audit Summary")}</h3>
        <div className="ard-summary-grid">
            {buildRows(score, auditSummary).map(([label, value]) => (
                <div className="ard-summary-row" key={label}>
                    <span className="ard-summary-label">{label}</span>
                    <span className="ard-summary-value">{n(value)}</span>
                </div>
            ))}
        </div>
    </section>
);

export default AuditSummary;
