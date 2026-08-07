import React from "react";
import { RiskScoreCell } from "./RiskScoreCell";
import { RiskRowActions } from "./RiskRowActions";
import { orDash, formatDate } from "./riskConstants";

const COLUMNS = [
    "Risk level",
    "Rank",
    "Asset Name",
    "IP Address",
    "Vendor",
    "Open Ports",
    "Zone",
    "Confidentiality Level",
    "Last Calculated",
    "Actions",
];

/**
 * "Overview" tab table. Rows are clickable — the per-asset detail screen is not
 * built yet, so onRowClick is optional and the row only looks interactive when
 * a handler is supplied.
 */
export const OverviewTable = ({ rows, onRowClick }) => (
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
                        <td>{orDash(row.ip_address)}</td>
                        <td>{orDash(row.vendor)}</td>
                        <td>{orDash(row.open_ports_count)}</td>
                        <td>{orDash(row.zone_name)}</td>
                        {/* Not returned by the risk API yet — requirements doc, issue 4. */}
                        <td className="risk-cell-pending">
                            {orDash(row.confidentiality_level)}
                        </td>
                        <td>{formatDate(row.calculated_at)}</td>
                        <RiskRowActions />
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

export default OverviewTable;
