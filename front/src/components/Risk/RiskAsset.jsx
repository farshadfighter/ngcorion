import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useSearchParams } from "react-router-dom";

import {
    fetchRiskDashboard,
    clearRecalcError,
    RISK_LEVEL_LABELS,
    setSort,
} from "../../store/riskSlice";
import { RiskAssetTable } from "./RiskAssetTable";
import "../../assets/RiskAsset.css";
import { t } from "../../i18n";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";

/**
 * Risk Asset screen: the hint bar plus the Overview / Audit Risk tabbed table.
 *
 * The KPI band and charts live on RiskIntelDashboard, a separate screen — this
 * page is only the asset table, matching the Figma mock.
 */
export const RiskAsset = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { items, isLoading, error, recalcError, sortBy, sortOrder } =
        useSelector((state) => state.risk);

    // ?level=critical, ?zone=<id>, ?incomplete=1 (the risk overview's figures and matrix)
    const [params, setParams] = useSearchParams();
    const riskLevel = RISK_LEVEL_LABELS[params.get("level")] ? params.get("level") : null;
    const zoneId = Number(params.get("zone")) || null;
    const incomplete = params.get("incomplete") === "1";
    const filtered = Boolean(riskLevel || zoneId || incomplete);
    const chips = [
        riskLevel && { key: "level", label: t("Risk level: {{level}}", { level: RISK_LEVEL_LABELS[riskLevel] }) },
        zoneId && { key: "zone", label: t("Zone: {{zone}}", { zone: items[0]?.zone_name || zoneId }) },
        incomplete && { key: "incomplete", label: t("Incomplete data") },
    ].filter(Boolean);
    const removeFilter = (key) => setParams((p) => { p.delete(key); return p; });

    useEffect(() => {
        dispatch(fetchRiskDashboard({ sortBy, sortOrder, riskLevel, zoneId, incomplete }));
    }, [dispatch, sortBy, sortOrder, riskLevel, zoneId, incomplete]);

    // Clicking the active column flips direction; a new column starts at desc,
    // which is what someone sorting by risk almost always wants first.
    const handleSort = (key) => {
        const nextOrder =
            key === sortBy && sortOrder === "desc" ? "asc" : "desc";
        dispatch(setSort({ sortBy: key, sortOrder: nextOrder }));
    };

    // A failed row recalculation is transient — show it, then let it clear.
    useEffect(() => {
        if (!recalcError) return;
        const timer = setTimeout(() => dispatch(clearRecalcError()), 5000);
        return () => clearTimeout(timer);
    }, [recalcError, dispatch]);

    if (isLoading && items.length === 0) {
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

    // An empty table here almost always means no risk scores have been
    // calculated yet (asset_risk_scores is empty), not that a filter excluded
    // everything — so say that rather than leaving a blank page.
    if (!isLoading && items.length === 0 && !filtered) {
        return (
            <div className="risk-page">
                <p className="risk-state">
                    {t("No risk scores have been calculated yet. Once assets are scored they appear here, ranked by risk.")}
                </p>
            </div>
        );
    }

    return (
        <div className="risk-page">
            <div className="rep-shortcut-row">
                {chips.length > 0 && (
                    <div className="risk-filters" role="group" aria-label={t("Filters")}>
                        {chips.map((c) => (
                            <button key={c.key} type="button" className="risk-filter-chip" title={t("Remove this filter")}
                                    onClick={() => removeFilter(c.key)}>
                                {c.label} <span aria-hidden="true">×</span>
                            </button>
                        ))}
                    </div>
                )}
                <ReportShortcut template="risk" className="bkm-btn bkm-btn-sm" />
            </div>
            {filtered && !isLoading && items.length === 0 && <p className="risk-state">{t("No assets match this filter.")}</p>}
            {recalcError && (
                <p className="risk-state risk-state-error risk-recalc-error">
                    {recalcError}
                </p>
            )}
            <RiskAssetTable
                rows={items}
                onRowClick={(row) => navigate(`/risk/assets/${row.asset_id}`)}
                sortBy={sortBy}
                sortOrder={sortOrder}
                onSort={handleSort}
            />
        </div>
    );
};

export default RiskAsset;
