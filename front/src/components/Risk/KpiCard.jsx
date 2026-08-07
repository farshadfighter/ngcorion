import React from "react";
import { formatNumber } from "./riskConstants";

/**
 * One KPI tile (Figma: 260x120, rx 5).
 * `value === null | undefined` means the backend cannot supply the number yet,
 * which renders as a muted dash rather than a misleading zero.
 */
export const KpiCard = ({ label, value, note }) => (
    <div className="risk-kpi">
        <span className="risk-kpi-label">{label}</span>
        {value === null || value === undefined ? (
            <span className="risk-kpi-value is-unavailable">—</span>
        ) : (
            <span className="risk-kpi-value">{formatNumber(value)}</span>
        )}
        {note && <span className="risk-kpi-note">{note}</span>}
    </div>
);

export default KpiCard;
