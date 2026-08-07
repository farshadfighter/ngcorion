import React from "react";

/**
 * The two per-row buttons from the Figma design (export + recalculate).
 * They are intentionally inert for now — the design does not define their
 * behaviour yet, so they render disabled rather than firing a request.
 * Clicks are stopped so they never trigger the row's own navigation.
 */
export const RiskRowActions = () => (
    <td className="risk-actions-cell" onClick={(e) => e.stopPropagation()}>
        <button
            type="button"
            className="risk-action-btn"
            disabled
            title="Export (not wired up yet)"
            aria-label="Export asset risk"
        >
            <i className="fa-solid fa-file-export" aria-hidden="true"></i>
        </button>
        <button
            type="button"
            className="risk-action-btn"
            disabled
            title="Recalculate (not wired up yet)"
            aria-label="Recalculate asset risk"
        >
            <i className="fa-solid fa-rotate-right" aria-hidden="true"></i>
        </button>
    </td>
);

export default RiskRowActions;
