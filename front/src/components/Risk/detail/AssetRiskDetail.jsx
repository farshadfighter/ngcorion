import React, { useEffect, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams, useNavigate } from "react-router-dom";

import {
    fetchAssetRiskDetail,
    fetchAssetRiskHistory,
    clearRiskDetail,
} from "../../../store/riskDetailSlice";
import { AssetRiskHeader } from "./AssetRiskHeader";
import { ConfidentialityZone } from "./ConfidentialityZone";
import { OpenPortsTable } from "./OpenPortsTable";
import { AuditSummary } from "./AuditSummary";
import { AuditFindingsTable } from "./AuditFindingsTable";
import { HardeningImpact } from "./HardeningImpact";
import { RiskHistory } from "./RiskHistory";
import "../../../assets/AssetRiskDetail.css";

/** Full risk breakdown for one asset, reached by clicking a row in Risk Asset. */
export const AssetRiskDetail = () => {
    const { assetId } = useParams();
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const {
        detail, findings, findingsError, isLoading, error,
        history, historyError, isLoadingHistory, isSavingProfile,
    } = useSelector((state) => state.riskDetail);

    useEffect(() => {
        dispatch(fetchAssetRiskDetail(assetId));
        dispatch(fetchAssetRiskHistory(assetId));
        return () => dispatch(clearRiskDetail());
    }, [dispatch, assetId]);

    // Editing the profile triggers a recalculation, which appends a history row.
    // Only the true -> false transition means a save just finished; firing on
    // mount too would duplicate the fetch above.
    const wasSaving = useRef(false);
    useEffect(() => {
        if (wasSaving.current && !isSavingProfile) {
            dispatch(fetchAssetRiskHistory(assetId));
        }
        wasSaving.current = isSavingProfile;
    }, [isSavingProfile, dispatch, assetId]);

    if (isLoading && !detail) {
        return (
            <div className="ard-page">
                <p className="ard-state">Loading asset risk…</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="ard-page">
                <p className="ard-state ard-state-error">
                    Failed to load asset risk: {error}
                </p>
            </div>
        );
    }

    if (!detail) return null;

    const score = detail.risk_score;

    return (
        <div className="ard-page">
            <button
                type="button"
                className="ard-back"
                onClick={() => navigate("/risk/assets")}
            >
                <i className="fa-solid fa-arrow-left" aria-hidden="true"></i> Back to
                Risk Asset
            </button>

            <AssetRiskHeader
                asset={detail.asset}
                score={score}
                incompleteData={detail.incomplete_data}
            />
            <ConfidentialityZone
                asset={detail.asset}
                score={score}
                assetId={detail.asset?.id}
            />
            <OpenPortsTable ports={detail.open_ports || []} />
            <AuditSummary score={score} auditSummary={detail.audit_summary} />
            <AuditFindingsTable findings={findings} error={findingsError} />
            <HardeningImpact
                score={score}
                auditSummary={detail.audit_summary}
                impact={detail.hardening_impact}
            />
            <RiskHistory
                history={history}
                isLoading={isLoadingHistory}
                error={historyError}
            />
        </div>
    );
};

export default AssetRiskDetail;
