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

/** "Audit Risk" tab: per-asset breakdown of active findings by severity. */
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
                        <td>{orDash(row.critical_findings_count)}</td>
                        <td>{orDash(row.high_findings_count)}</td>
                        <td>{orDash(row.medium_findings_count)}</td>
                        <td>{orDash(row.low_findings_count)}</td>
                        <RiskRowActions />
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

export default AuditRiskTable;
