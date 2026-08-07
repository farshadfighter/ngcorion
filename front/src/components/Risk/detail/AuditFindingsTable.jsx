import React from "react";
import { orDash, titleCase, formatDate } from "../riskConstants";

const COLUMNS = [
    "Check ID",
    "Check Title",
    "Severity",
    "Level",
    "Vdom",
    "Actual Value",
    "Hardening Status",
    "Verification Status",
    "Last Update",
];

/**
 * Audit findings for the session the risk score was calculated from.
 *
 * Rows come from GET /api/audit/sessions/{id}/results, which is guarded by
 * AUDITING read — hence findingsError, which is shown instead of an empty table
 * when the user lacks that permission.
 *
 * Hardening Status / Verification Status are not on that payload; the hardening
 * link exists in the DB (HardeningAction.verification_passed) but no endpoint
 * exposes it per finding — see RISK_FRONTEND_BACKEND_REQUIREMENTS.md.
 */
export const AuditFindingsTable = ({ findings, error }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">Audit Findings</h3>
        {error ? (
            <p className="ard-notice">{error}</p>
        ) : (
            <div className="ard-table-wrapper">
                <table className="ard-table">
                    <thead>
                        <tr>
                            {COLUMNS.map((label) => (
                                <th key={label}>{label}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {findings.length === 0 && (
                            <tr>
                                <td colSpan={COLUMNS.length} className="ard-table-empty">
                                    No audit findings for this asset.
                                </td>
                            </tr>
                        )}
                        {findings.map((finding) => (
                            <tr key={finding.id}>
                                <td>{orDash(finding.check_number)}</td>
                                <td className="ard-cell-wide">{orDash(finding.check_title)}</td>
                                <td>{finding.severity ? titleCase(finding.severity) : "-"}</td>
                                <td>{orDash(finding.level)}</td>
                                <td>{orDash(finding.vdom)}</td>
                                <td className="ard-cell-wide">
                                    {orDash(finding.evidence_snippet)}
                                </td>
                                {/* Not exposed per finding by any endpoint yet. */}
                                <td className="ard-cell-pending">—</td>
                                <td className="ard-cell-pending">—</td>
                                <td>{formatDate(finding.checked_at)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        )}
    </section>
);

export default AuditFindingsTable;
