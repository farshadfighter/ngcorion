import React from "react";
import { orDash } from "./riskConstants";
import { RiskLevelBadge } from "./RiskLevelBadge";

const COLUMNS = [
    "Number",
    "Asset Name",
    "Hostname",
    "Type",
    "Zone",
    "Manufacturer",
    "Model",
    "Risk Score",
    "Risk Level",
];

/** "Top 10 Risky Assets" table on the Risk Intelligence dashboard. */
export const TopRiskyAssetsTable = ({ rows }) => (
    <section className="risk-card risk-table-card">
        <h3 className="risk-card-title">Top 10 Risky Assets</h3>
        <div className="risk-table-wrapper risk-table-wrapper--inset">
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
                                No risk scores calculated yet.
                            </td>
                        </tr>
                    )}
                    {rows.map((row, index) => (
                        <tr key={row.asset_id}>
                            <td>{row.rank ?? index + 1}</td>
                            <td>{orDash(row.asset_name)}</td>
                            <td>{orDash(row.hostname)}</td>
                            <td>{orDash(row.asset_type)}</td>
                            <td>{orDash(row.zone_name)}</td>
                            <td>{orDash(row.vendor)}</td>
                            <td>{orDash(row.model)}</td>
                            <td>{orDash(row.final_risk_score)}</td>
                            <td>
                                <RiskLevelBadge level={row.risk_level} />
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </section>
);

export default TopRiskyAssetsTable;
