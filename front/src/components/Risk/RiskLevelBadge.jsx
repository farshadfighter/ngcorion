import React from "react";

import { RISK_LEVEL_BADGES, titleCase } from "./riskConstants";

/**
 * Coloured pill for a risk level, so severity is readable without decoding a
 * number. Same shape as the status pills in the Hardening and Auditing tables.
 */
export const RiskLevelBadge = ({ level }) => {
    if (!level) return <span className="risk-muted">-</span>;

    const colors = RISK_LEVEL_BADGES[level];
    return (
        <span
            className="risk-level-badge"
            style={
                colors ? { background: colors.bg, color: colors.fg } : undefined
            }
        >
            {titleCase(level)}
        </span>
    );
};

export default RiskLevelBadge;
