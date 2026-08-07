import React from "react";
import { RISK_LEVEL_LABELS } from "../../../store/riskSlice";
import { titleCase, formatDate, orDash } from "../riskConstants";

/**
 * The four summary tiles at the top of the asset risk detail page.
 * Figma: 240x144 rx=5; the first tile is filled #14213D, the rest #F5F5F5.
 */
const Tile = ({ label, value, caption, variant }) => (
    <div className={`ard-tile ${variant === "dark" ? "is-dark" : ""}`}>
        <span className="ard-tile-value">{value}</span>
        <span className="ard-tile-label">{label}</span>
        {caption && <span className="ard-tile-caption">{caption}</span>}
    </div>
);

export const AssetRiskHeader = ({ asset, score, incompleteData }) => {
    const level = score?.risk_level;

    return (
        <section className="ard-card ard-header">
            <div className="ard-tiles">
                <Tile
                    variant="dark"
                    value={score?.final_risk_score ?? "-"}
                    label="Risk Score"
                />
                <Tile
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
