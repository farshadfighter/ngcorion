import React, { useMemo, useState } from "react";

import { RiskNotice } from "./RiskNotice";
import { RiskTabs } from "./RiskTabs";
import { RiskSearch } from "./RiskSearch";
import { OverviewTable } from "./OverviewTable";
import { AuditRiskTable } from "./AuditRiskTable";

const TABS = [
    { key: "overview", label: "Overview" },
    { key: "audit", label: "Audit Risk" },
];

/** Fields the search box matches against, mirroring the backend's ?search=. */
const SEARCH_FIELDS = ["asset_name", "hostname", "ip_address"];

const matchesSearch = (row, term) =>
    SEARCH_FIELDS.some((field) =>
        String(row[field] || "").toLowerCase().includes(term)
    );

/**
 * The tabbed asset table below the KPI dashboard: a hint bar, Overview /
 * Audit Risk tabs, a search box, and the matching table.
 *
 * Filtering is client-side because the rows are already loaded for the KPI
 * aggregates; once GET /api/risk/summary exists this should move to the
 * backend's ?search= parameter instead.
 */
export const RiskAssetTable = ({ rows, onRowClick }) => {
    const [activeTab, setActiveTab] = useState("overview");
    const [search, setSearch] = useState("");

    const visibleRows = useMemo(() => {
        const term = search.trim().toLowerCase();
        if (!term) return rows;
        return rows.filter((row) => matchesSearch(row, term));
    }, [rows, search]);

    return (
        <section className="risk-asset-table">
            <RiskNotice>
                Click on the asset to view more information about asset risk.
            </RiskNotice>

            <RiskTabs tabs={TABS} active={activeTab} onChange={setActiveTab} />
            <RiskSearch value={search} onChange={setSearch} />

            {activeTab === "overview" ? (
                <OverviewTable rows={visibleRows} onRowClick={onRowClick} />
            ) : (
                <AuditRiskTable rows={visibleRows} onRowClick={onRowClick} />
            )}
        </section>
    );
};

export default RiskAssetTable;
