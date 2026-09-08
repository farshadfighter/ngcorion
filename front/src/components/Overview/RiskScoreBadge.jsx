import React from "react";

import { RISK_LEVEL_BADGES } from "../Risk/riskConstants";

/**
 * A risk score tinted by the level it falls in.
 *
 * The dashboard tables print the score next to its Risk Level badge, but the
 * score was plain text — so the row showed the severity twice and coloured it
 * once. Both now take their colour from RISK_LEVEL_BADGES, keyed by the same
 * level, which is the single source the Risk pages and the audit/hardening
 * pills already use.
 *
 * Falls back to the neutral chip when the level is unknown, and to a plain dash
 * when there is no score at all.
 */
export const RiskScoreBadge = ({ score, level }) => {
    if (score === null || score === undefined) {
        return <span className="risk-muted">-</span>;
    }

    const colors = level ? RISK_LEVEL_BADGES[level] : null;

    return (
        <span
            className="ov-risk-score"
            style={colors ? { background: colors.bg, color: colors.fg } : undefined}
        >
            {Math.round(score)}
        </span>
    );
};

export default RiskScoreBadge;
