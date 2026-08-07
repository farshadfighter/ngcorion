import React from "react";
import { RISK_LEVEL_COLORS } from "./riskConstants";

/**
 * The dark score box that opens every table row in the Figma design.
 * Figma fills it with #14213D; when a risk_level is known we tint the left
 * edge with the level colour so the severity is readable at a glance.
 */
export const RiskScoreCell = ({ score, level }) => (
    <td className="risk-score-cell">
        <div
            className="risk-score-box"
            style={
                level && RISK_LEVEL_COLORS[level]
                    ? { borderLeftColor: RISK_LEVEL_COLORS[level] }
                    : undefined
            }
        >
            {score === null || score === undefined ? "-" : Math.round(score)}
        </div>
    </td>
);

export default RiskScoreCell;
