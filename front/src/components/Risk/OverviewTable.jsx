import React from "react";
import { RiskScoreCell } from "./RiskScoreCell";
import { RiskRowActions } from "./RiskRowActions";
import { RiskLevelBadge } from "./RiskLevelBadge";
import { SortableHeader } from "./SortableHeader";
import { orDash, titleCase, formatDate } from "./riskConstants";
import { t } from "../../i18n";

/**
 * Open Ports and Zone are deliberately absent: the client asked for them to be
 * dropped from this table. Both still drive the score and remain on the asset
 * detail screen.
 *
 * `key` marks a sortable column; the value is a sort_by the backend accepts.
 * "Risk level" sorts by final_risk_score rather than risk_level, because
 * risk_level is a string column — ordering by it is alphabetical, which would
 * put critical next to low. The level is derived from the score, so sorting by
 * score yields exactly the severity order.
 */
const COLUMNS = [
    { label: t("Risk Score"), key: "final_risk_score" },
    t("Rank"),
    { label: t("Asset Name"), key: "asset_name" },
    "IP Address",
    t("Vendor"),
    { label: t("Risk Level"), key: "final_risk_score" },
    t("Confidentiality Level"),
    { label: t("Last Calculated"), key: "calculated_at" },
    t("Actions"),
];

export const OverviewTable = ({ rows, onRowClick, sortBy, sortOrder, onSort }) => (
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
                            {t("No assets match this view.")}
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
                        <td>
                            <RiskLevelBadge level={row.risk_level} />
                        </td>
                        <td>
                            {row.confidentiality_level
                                ? titleCase(row.confidentiality_level)
                                : "-"}
                        </td>
                        <td>{formatDate(row.calculated_at)}</td>
                        <RiskRowActions row={row} />
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

export default OverviewTable;
