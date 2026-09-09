import React from "react";
import { RISK_LEVEL_LABELS } from "../../../store/riskSlice";
import { titleCase, formatDate, orDash, RISK_LEVEL_BADGES } from "../riskConstants";

/**
 * The four summary tiles at the top of the asset risk detail page.
 * Figma: 240x144 rx=5.
 *
 * The score and level tiles take the level's colour from RISK_LEVEL_BADGES, the
 * same palette the tables and charts use, so severity reads the same wherever
 * it appears. They were both a flat #14213D/#F5F5F5, which said nothing about
 * how bad the number was. The remaining two tiles carry no severity and keep
 * the neutral fill.
 */
const Tile = ({ label, value, caption, variant, colors }) => (
    <div
        className={`ard-tile ${variant === "dark" ? "is-dark" : ""}`}
        style={colors ? { background: colors.bg, color: colors.fg } : undefined}
    >
        <span className="ard-tile-value" style={colors ? { color: colors.fg } : undefined}>
            {value}
        </span>
        <span className="ard-tile-label" style={colors ? { color: colors.fg } : undefined}>
            {label}
        </span>
        {caption && <span className="ard-tile-caption">{caption}</span>}
    </div>
);

export const AssetRiskHeader = ({ asset, score, incompleteData }) => {
    const level = score?.risk_level;
    const levelColors = level ? RISK_LEVEL_BADGES[level] : null;

    return (
        <section className="ard-card ard-header">
            <div className="ard-tiles">
                <Tile
                    variant={levelColors ? undefined : "dark"}
                    colors={levelColors}
                    value={score?.final_risk_score ?? "-"}
                    label="Risk Score"
                />
                <Tile
                    colors={levelColors}
                    value={level ? RISK_LEVEL_LABELS[level] || titleCase(level) : "-"}
                    label="Risk Level"
                />
                <Tile
                    value={formatDate(score?.calculated_at)}
                    label="Last Calculated"
                />
                <Tile
                    value={incompleteData ? "Incomplete" : "Complete"}
                    label="Data Completeness Status"
                />
            </div>

            <dl className="ard-facts">
                <div>
                    <dt>Asset</dt>
                    <dd>{orDash(asset?.name)}</dd>
                </div>
                <div>
                    <dt>IP Address</dt>
                    <dd>{orDash(asset?.ip_address)}</dd>
                </div>
                <div>
                    <dt>Vendor</dt>
                    <dd>{orDash(asset?.vendor)}</dd>
                </div>
                <div>
                    <dt>Product</dt>
                    <dd>{orDash(asset?.product)}</dd>
                </div>
            </dl>
        </section>
    );
};

export default AssetRiskHeader;
