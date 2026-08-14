import React from "react";
import { RiskScoreCell } from "./RiskScoreCell";
import { RiskRowActions } from "./RiskRowActions";
import { RiskLevelBadge } from "./RiskLevelBadge";
import { SortableHeader } from "./SortableHeader";
import { orDash } from "./riskConstants";

/* The first column is the score box, so it is labelled as the score; the
   separate "Risk Level" column holds the badge. Both sort by final_risk_score —
   see the note in OverviewTable on why not by risk_level. */
const COLUMNS = [
    { label: "Risk Score", key: "final_risk_score" },
    "Rank",
    { label: "Asset Name", key: "asset_name" },
    { label: "Risk Level", key: "final_risk_score" },
    "Critical Findings",
    "High Findings",
    "Medium Findings",
    "Low Findings",
    "Actions",
];

/** "Audit Risk" tab: per-asset breakdown of active findings by severity. */
export const AuditRiskTable = ({ rows, onRowClick, sortBy, sortOrder, onSort }) => (
    <div className="risk-table-wrapper">
        <table className="risk-table">
            <SortableHeader
                columns={COLUMNS}
                sortBy={sortBy}
                sortOrder={sortOrder}
                onSort={onSort}
            />
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
                        <td>
                            <RiskLevelBadge level={row.risk_level} />
                        </td>
                        <td>{orDash(row.critical_findings_count)}</td>
                        <td>{orDash(row.high_findings_count)}</td>
                        <td>{orDash(row.medium_findings_count)}</td>
                        <td>{orDash(row.low_findings_count)}</td>
                        <RiskRowActions row={row} />
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

export default AuditRiskTable;
