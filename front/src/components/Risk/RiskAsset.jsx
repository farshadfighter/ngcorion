import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";

import { fetchRiskDashboard, clearRecalcError } from "../../store/riskSlice";
import { RiskAssetTable } from "./RiskAssetTable";
import "../../assets/RiskAsset.css";

/**
 * Risk Asset screen: the hint bar plus the Overview / Audit Risk tabbed table.
 *
 * The KPI band and charts live on RiskIntelDashboard, a separate screen — this
 * page is only the asset table, matching the Figma mock.
 */
export const RiskAsset = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { items, isLoading, error, recalcError } = useSelector(
        (state) => state.risk
    );

    useEffect(() => {
        dispatch(fetchRiskDashboard());
    }, [dispatch]);

    // A failed row recalculation is transient — show it, then let it clear.
    useEffect(() => {
        if (!recalcError) return;
        const timer = setTimeout(() => dispatch(clearRecalcError()), 5000);
        return () => clearTimeout(timer);
    }, [recalcError, dispatch]);

    if (isLoading && items.length === 0) {
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

    // An empty table here almost always means no risk scores have been
    // calculated yet (asset_risk_scores is empty), not that a filter excluded
    // everything — so say that rather than leaving a blank page.
    if (!isLoading && items.length === 0) {
        return (
            <div className="risk-page">
                <p className="risk-state">
                    No risk scores have been calculated yet. Once assets are
                    scored they appear here, ranked by risk.
                </p>
            </div>
        );
    }

    return (
        <div className="risk-page">
            {recalcError && (
                <p className="risk-state risk-state-error risk-recalc-error">
                    {recalcError}
                </p>
            )}
            <RiskAssetTable
                rows={items}
                onRowClick={(row) => navigate(`/risk/assets/${row.asset_id}`)}
            />
        </div>
    );
};

export default RiskAsset;
