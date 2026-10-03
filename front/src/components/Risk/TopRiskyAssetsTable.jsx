import React from "react";
import { orDash } from "./riskConstants";
import { RiskLevelBadge } from "./RiskLevelBadge";
import { t, n } from "../../i18n";

const COLUMNS = [
    t("Number"),
    t("Asset Name"),
    t("Hostname"),
    t("Type"),
    t("Zone"),
    t("Manufacturer"),
    t("Model"),
    t("Risk Score"),
    t("Risk Level"),
];

/** "Top 10 Risky Assets" table on the Risk Intelligence dashboard. */
export const TopRiskyAssetsTable = ({ rows }) => (
    <section className="risk-card risk-table-card">
        <h3 className="risk-card-title">{t("Top 10 Risky Assets")}</h3>
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
                                {t("No risk scores calculated yet.")}
                            </td>
                        </tr>
                    )}
                    {rows.map((row, index) => (
                        <tr key={row.asset_id}>
                            <td>{n(row.rank ?? index + 1)}</td>
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
