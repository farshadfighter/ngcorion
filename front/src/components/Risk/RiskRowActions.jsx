import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";

import api from "../../config/api";
import { usePermission } from "../../hooks/usePermission";
import { recalculateAssetRisk } from "../../store/riskSlice";

/**
 * The two per-row buttons from the Figma design:
 *   - recalculate: POST /api/risk/assets/{id}/calculate, needs RISK:write
 *   - export:      GET  /api/risk/assets/{id}/export/json, needs RISK:read
 *
 * Export goes through the axios instance rather than a plain <a download> so it
 * carries the bearer token; the response is turned into a blob and saved.
 * Clicks are stopped so neither button triggers the row's own navigation.
 */
export const RiskRowActions = ({ row }) => {
    const dispatch = useDispatch();
    const canWrite = usePermission("risk", "write");
    const recalculatingId = useSelector((state) => state.risk.recalculatingId);
    const [isExporting, setIsExporting] = useState(false);

    const assetId = row?.asset_id;
    const isRecalculating = recalculatingId === assetId;

    const handleExport = async () => {
        if (!assetId || isExporting) return;
        setIsExporting(true);
        try {
            const res = await api.get(`/api/risk/assets/${assetId}/export/json`);
            const blob = new Blob([JSON.stringify(res.data, null, 2)], {
                type: "application/json",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            const safeName = String(row?.asset_name || `asset-${assetId}`)
                .replace(/[^a-z0-9._-]+/gi, "_");
            a.download = `risk-${safeName}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            // Let the click be processed before the object URL is torn down.
            setTimeout(() => URL.revokeObjectURL(url), 0);
        } catch {
            // 401/403 are already surfaced globally by the axios interceptor.
        } finally {
            setIsExporting(false);
        }
    };

    return (
        <td className="risk-actions-cell" onClick={(e) => e.stopPropagation()}>
            <button
                type="button"
                className="risk-action-btn"
                onClick={handleExport}
                disabled={isExporting || !assetId}
                title="Export this asset's risk as JSON"
                aria-label="Export asset risk"
            >
                <i
                    className={
                        isExporting
                            ? "fa-solid fa-spinner fa-spin"
                            : "fa-solid fa-file-export"
                    }
                    aria-hidden="true"
                />
            </button>
            <button
                type="button"
                className="risk-action-btn"
                onClick={() => assetId && dispatch(recalculateAssetRisk(assetId))}
                disabled={!canWrite || isRecalculating || !assetId}
                title={
                    canWrite
                        ? "Recalculate this asset's risk score"
                        : "Recalculating requires risk write permission"
                }
                aria-label="Recalculate asset risk"
            >
                <i
                    className={
                        isRecalculating
                            ? "fa-solid fa-rotate-right fa-spin"
                            : "fa-solid fa-rotate-right"
                    }
                    aria-hidden="true"
                />
            </button>
        </td>
    );
};

export default RiskRowActions;
