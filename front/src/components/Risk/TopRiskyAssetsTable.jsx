import React from "react";
import { RISK_LEVEL_COLORS, orDash, titleCase } from "./riskConstants";
import { RISK_LEVEL_LABELS } from "../../store/riskSlice";

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
                            {/* asset_type is not in the payload yet — requirements doc, issue 4b. */}
                            <td className="risk-cell-pending">{orDash(row.asset_type)}</td>
                            <td>{orDash(row.zone_name)}</td>
                            <td>{orDash(row.vendor)}</td>
                            <td>{orDash(row.model)}</td>
                            <td>{orDash(row.final_risk_score)}</td>
                            <td>
                                {row.risk_level ? (
                                    <span
                                        className="risk-level-pill"
                                        style={{
                                            background:
                                                RISK_LEVEL_COLORS[row.risk_level] || "#9AA5B5",
                                        }}
                                    >
                                        {RISK_LEVEL_LABELS[row.risk_level] ||
                                            titleCase(row.risk_level)}
                                    </span>
                                ) : (
                                    "-"
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </section>
);

export default TopRiskyAssetsTable;
