import React from "react";
import { RISK_LEVEL_BADGES } from "./riskConstants";

/**
 * The score box that opens every table row.
 *
 * It used to be a fixed dark #14213D fill with only the left edge tinted by the
 * level, so two assets with very different severities looked identical at a
 * glance. It now takes the same palette as the Risk Level badge beside it
 * (RISK_LEVEL_BADGES), so score and level always read as one colour: the score
 * IS the level, and showing them in different colours invited exactly the
 * mismatch this was reported for.
 *
 * Falls back to the neutral dark box when the level is unknown.
 */
export const RiskScoreCell = ({ score, level }) => {
    const colors = level ? RISK_LEVEL_BADGES[level] : null;

    return (
        <td className="risk-score-cell">
            <div
                className="risk-score-box"
                style={
                    colors
                        ? { background: colors.bg, color: colors.fg }
                        : undefined
                }
            >
                {score === null || score === undefined ? "-" : Math.round(score)}
            </div>
        </td>
    );
};

export default RiskScoreCell;
