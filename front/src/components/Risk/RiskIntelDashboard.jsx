import React, { useEffect, useMemo } from "react";
import { useDispatch, useSelector } from "react-redux";

import { fetchRiskDashboard, RISK_LEVEL_LABELS } from "../../store/riskSlice";
import { KpiCard } from "./KpiCard";
import { DonutCard } from "./DonutCard";
import { TrendCard } from "./TrendCard";
import { TopRiskyAssetsTable } from "./TopRiskyAssetsTable";
import { RISK_LEVEL_COLORS, CATEGORY_COLORS, titleCase } from "./riskConstants";
import "../../assets/RiskAsset.css";

/**
 * Risk Intelligence overview: the KPI band and the four charts.
 *
 * This is a separate screen from Risk Asset (which is the tabbed asset table).
 * It has no route in the sidebar yet — the Figma for its placement is pending.
 */
export const RiskIntelDashboard = () => {
    const dispatch = useDispatch();
    const { items, summary, trend, trendMessage, isLoading, error } = useSelector(
        (state) => state.risk
    );

    // Only the Top 10 table consumes `items` here, so ask for 10 rows rather
    // than the default 100 — the other 90 were fetched and thrown away.
    useEffect(() => {
        dispatch(fetchRiskDashboard({ pageSize: 10 }));
    }, [dispatch]);

    const riskLevelData = useMemo(
        () =>
            (summary?.by_risk_level || []).map((entry) => ({
                ...entry,
                label: RISK_LEVEL_LABELS[entry.key] || titleCase(entry.key),
            })),
        [summary]
    );

    const zoneData = useMemo(
        () =>
            (summary?.by_zone || []).map((entry) => ({
                ...entry,
                label: entry.key === "unclassified" ? "Unassigned" : entry.key,
            })),
        [summary]
    );

    const confidentialityData = useMemo(
        () =>
            (summary?.by_confidentiality || []).map((entry) => ({
                ...entry,
                label: titleCase(entry.key),
            })),
        [summary]
    );

    // Rows arrive sorted by final_risk_score desc, so the first ten are the top ten.
    const topAssets = useMemo(() => items.slice(0, 10), [items]);

    if (isLoading && !summary) {
        return (
            <div className="risk-page">
                <p className="risk-state">Loading risk data…</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="risk-page">
                <p className="risk-state risk-state-error">
                    Failed to load risk data: {error}
                </p>
            </div>
        );
    }

    const totals = summary?.totals || {};
    const levelCount = (level) =>
        riskLevelData.find((entry) => entry.key === level)?.count ?? 0;

    const byIndex = (entry, all) =>
        CATEGORY_COLORS[all.indexOf(entry) % CATEGORY_COLORS.length];

    return (
        <div className="risk-page">
            <section className="risk-card risk-kpi-panel">
                <div className="risk-kpi-grid">
                    <KpiCard label="Number of assets" value={totals.total_assets} />
                    <KpiCard label="Critical Risk assets" value={levelCount("critical")} />
                    <KpiCard label="Very High Risk assets" value={levelCount("very_high")} />
                    <KpiCard label="High Risk assets" value={levelCount("high")} />
                    <KpiCard label="Risk Score average" value={totals.risk_score_average} />
                    <KpiCard
                        label="Number of incomplete assets"
                        value={totals.incomplete_assets}
                    />
                    <KpiCard label="Number of Open Ports" value={totals.open_ports_total} />
                    <KpiCard
                        label="Non-conformity asset"
                        value={totals.non_conformity_assets}
                        note="assets with active findings"
                    />
                    <KpiCard
                        label="Number of fixed section by hardening"
                        value={totals.fixed_by_hardening_total}
                    />
                </div>
            </section>

            <div className="risk-chart-grid">
                <DonutCard
                    title="Asset by Risk level"
                    data={riskLevelData}
                    colorFor={(entry) => RISK_LEVEL_COLORS[entry.key] || "#9AA5B5"}
                    emptyMessage="No scored assets yet."
                />
                <DonutCard
                    title="Asset by Zone"
                    data={zoneData}
                    colorFor={byIndex}
                    emptyMessage={
                        "No zones assigned yet.\n" +
                        "Run the risk seed to create the default zones."
                    }
                />
                <DonutCard
                    title="Asset by confidentiality level"
                    data={confidentialityData}
                    colorFor={byIndex}
                    emptyMessage="No assets carry a confidentiality level yet."
                />

                <TrendCard points={trend} message={trendMessage} />
            </div>

            <TopRiskyAssetsTable rows={topAssets} />
        </div>
    );
};

export default RiskIntelDashboard;
