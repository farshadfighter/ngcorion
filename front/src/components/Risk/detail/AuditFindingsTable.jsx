import React from "react";
import { orDash, titleCase, formatDate } from "../riskConstants";
import { AUDIT_NOW, HARDENING, VERIFICATION, statusOf } from "./findingStatus";
import { t } from "../../../i18n";

const Chip = ({ status, title }) =>
    status ? <span className={`ard-chip is-${status.tone}`} title={title || status.hint}>{status.label}</span>
        : <span className="ard-cell-pending">—</span>;

/**
 * Audit findings of the audit the risk score reads: the controls that failed in it, failing now or fixed
 * since, with where their hardening stands and whether the fix was verified. Rows from
 * GET /api/risk/assets/{id}/findings; the actual value only for who may read the audit itself.
 */
export const AuditFindingsTable = ({ findings, error, actualShown }) => {
    const withVdom = findings.some((f) => f.vdom);
    const columns = [
        t("Check ID"), t("Check Title"), t("Severity"), t("Level"),
        ...(withVdom ? [t("Vdom")] : []),
        ...(actualShown ? [t("Actual Value")] : []),
        t("Now"), t("Hardening Status"), t("Verification Status"), t("Last Update"),
    ];
    return (
        <section className="ard-card">
            <h3 className="ard-card-title">{t("Audit Findings")}</h3>
            {error ? (
                <p className="ard-notice">{error}</p>
            ) : (
                <>
                    {!actualShown && findings.length > 0 && (
                        <p className="ard-findings-note">{t("The actual values are shown to who may read this audit (Auditing permission).")}</p>
                    )}
                    <div className="ard-table-wrapper">
                        <table className="ard-table">
                            <thead>
                                <tr>{columns.map((label) => <th key={label}>{label}</th>)}</tr>
                            </thead>
                            <tbody>
                                {findings.length === 0 && (
                                    <tr>
                                        <td colSpan={columns.length} className="ard-table-empty">
                                            {t("No audit findings for this asset.")}
                                        </td>
                                    </tr>
                                )}
                                {findings.map((f) => (
                                    <tr key={f.id}>
                                        <td>{orDash(f.check_number)}</td>
                                        <td className="ard-cell-wide">{orDash(f.check_title)}</td>
                                        <td>{f.severity ? titleCase(f.severity) : "-"}</td>
                                        <td>{orDash(f.level)}</td>
                                        {withVdom && <td>{orDash(f.vdom)}</td>}
                                        {actualShown && <td className="ard-cell-wide">{orDash(f.actual_value)}</td>}
                                        <td><Chip status={statusOf(AUDIT_NOW, f.audit_status)} /></td>
                                        <td>
                                            <Chip status={statusOf(HARDENING, f.hardening_status)} title={f.hardening_error || undefined} />
                                            {f.risk_accepted && <span className="ard-chip is-accepted">{t("Risk accepted")}</span>}
                                        </td>
                                        <td><Chip status={statusOf(VERIFICATION, f.verification_status)} /></td>
                                        <td>{formatDate(f.last_update)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </>
            )}
        </section>
    );
};

export default AuditFindingsTable;
