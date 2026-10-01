import React, { useEffect, useMemo } from "react";
import { useDispatch, useSelector } from "react-redux";

import { fetchRiskDashboard, RISK_LEVEL_LABELS } from "../../store/riskSlice";
import { KpiCard } from "./KpiCard";
import { DonutCard } from "./DonutCard";
import { TrendCard } from "./TrendCard";
import { TopRiskyAssetsTable } from "./TopRiskyAssetsTable";
import { RISK_LEVEL_COLORS, CATEGORY_COLORS, titleCase } from "./riskConstants";
import "../../assets/RiskAsset.css";
import { t } from "../../i18n";

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

    /* Zones that differ only in spacing around the slash are the same place:
       the seed creates "Internet / Public" while an operator adding one by hand
       types "Internet/Public", and the chart drew them as two slices with two
       colours. Merge on a normalised key and keep the first spelling seen, so
       one zone is one slice. */
    const zoneData = useMemo(() => {
        const merged = new Map();
        for (const entry of summary?.by_zone || []) {
            const label =
                entry.key === "unclassified" ? t("Unassigned") : entry.key;
            const key = String(label).toLowerCase().replace(/\s*\/\s*/g, "/").trim();
            const existing = merged.get(key);
            if (existing) {
                existing.count += entry.count || 0;
            } else {
                merged.set(key, { ...entry, label, count: entry.count || 0 });
            }
        }
        return [...merged.values()];
    }, [summary]);

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
                <p className="risk-state">{t("Loading risk data…")}</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="risk-page">
                <p className="risk-state risk-state-error">
                    {t("Failed to load risk data: {{error}}", { error })}
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
                    <KpiCard label={t("Number of assets")} value={totals.total_assets} />
                    <KpiCard label={t("Critical Risk assets")} value={levelCount("critical")} />
                    <KpiCard label={t("High Risk assets")} value={levelCount("high")} />
                    <KpiCard label={t("Medium Risk assets")} value={levelCount("medium")} />
                    <KpiCard label={t("Risk Score average")} value={totals.risk_score_average} />
                    <KpiCard
                        label={t("Number of incomplete assets")}
                        value={totals.incomplete_assets}
                    />
                    <KpiCard label={t("Number of Open Ports")} value={totals.open_ports_total} />
                    <KpiCard
                        label={t("Non-conformity asset")}
                        value={totals.non_conformity_assets}
                        note={t("assets with active findings")}
                    />
                    <KpiCard
                        label={t("Number of fixed section by hardening")}
                        value={totals.fixed_by_hardening_total}
                    />
                </div>
            </section>

            <div className="risk-chart-grid">
                <DonutCard
                    title={t("Asset by Risk level")}
                    data={riskLevelData}
                    colorFor={(entry) => RISK_LEVEL_COLORS[entry.key] || "#9AA5B5"}
                    emptyMessage={t("No scored assets yet.")}
                />
                <DonutCard
                    title={t("Asset by Zone")}
                    data={zoneData}
                    colorFor={byIndex}
                    emptyMessage={
                        t("No zones assigned yet.") + "\n" +
                        t("Run the risk seed to create the default zones.")
                    }
                />
                <DonutCard
                    title={t("Asset by confidentiality level")}
                    data={confidentialityData}
                    colorFor={byIndex}
                    emptyMessage={t("No assets carry a confidentiality level yet.")}
                />

                <TrendCard points={trend} message={trendMessage} />
            </div>

            <TopRiskyAssetsTable rows={topAssets} />
        </div>
    );
};

export default RiskIntelDashboard;
