import React from "react";
import { RiskScoreCell } from "./RiskScoreCell";
import { RiskRowActions } from "./RiskRowActions";
import { orDash, titleCase } from "./riskConstants";

const COLUMNS = [
    "Risk level",
    "Rank",
    "Asset Name",
    "Risk Level",
    "Critical Findings",
    "High Findings",
    "Medium Findings",
    "Low Findings",
    "Actions",
];

/**
 * "Audit Risk" tab table.
 *
 * The four *_findings_count fields exist on AssetRiskScore but are NOT part of
 * the list payload today (only _score_to_dict returns them), so they render as
 * pending — see front/RISK_FRONTEND_BACKEND_REQUIREMENTS.md, issue 4c.
 */
export const AuditRiskTable = ({ rows, onRowClick }) => (
    <div className="risk-table-wrapper">
        <table className="risk-table">
            <thead>
                <tr>
                    {COLUMNS.map((label) => (
                        <th key={label}>{label}</th>
                    ))}
                </tr>
            </thead>
            <tbody>
                {rows.length === 0 && (
                    <tr>
                        <td colSpan={COLUMNS.length} className="risk-table-empty">
                            No assets match this view.
                        </td>
                    </tr>
                )}
                {rows.map((row) => (
                    <tr
                        key={row.asset_id}
                        className={onRowClick ? "is-clickable" : ""}
                        onClick={onRowClick ? () => onRowClick(row) : undefined}
                    >
                        <RiskScoreCell score={row.final_risk_score} level={row.risk_level} />
                        <td>{orDash(row.rank)}</td>
                        <td>{orDash(row.asset_name)}</td>
                        <td>{row.risk_level ? titleCase(row.risk_level) : "-"}</td>
                        <td className="risk-cell-pending">
                            {orDash(row.critical_findings_count)}
                        </td>
                        <td className="risk-cell-pending">
                            {orDash(row.high_findings_count)}
                        </td>
                        <td className="risk-cell-pending">
                            {orDash(row.medium_findings_count)}
                        </td>
                        <td className="risk-cell-pending">
                            {orDash(row.low_findings_count)}
                        </td>
                        <RiskRowActions />
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

export default AuditRiskTable;
