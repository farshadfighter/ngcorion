import React from "react";
import { orDash, titleCase } from "../riskConstants";

/**
 * "Confidentiality & Zone" block: two score boxes with their labels.
 * The edit pencils from the Figma mock are rendered inert — the design does not
 * define the edit flow yet, and PUT /api/risk/assets/{id}/profile takes
 * criticality + zone, not confidentiality.
 */
export const ConfidentialityZone = ({ asset, score }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">Confidentiality &amp; Zone</h3>
        <div className="ard-cz-grid">
            <div className="ard-cz-col">
                <div className="ard-cz-head">
                    <span>Confidentiality Score</span>
                    <span>Confidentiality</span>
                    <span>Actions</span>
                </div>
                <div className="ard-cz-row">
                    <span className="ard-score-box">
                        {score?.criticality_score ?? "-"}
                    </span>
                    <span>
                        {asset?.confidentiality_level
                            ? titleCase(asset.confidentiality_level)
                            : "-"}
                    </span>
                    <button
                        type="button"
                        className="ard-icon-btn"
                        disabled
                        title="Edit (not wired up yet)"
                        aria-label="Edit confidentiality"
                    >
                        <i className="fa-solid fa-pen" aria-hidden="true"></i>
                    </button>
                </div>
            </div>

            <div className="ard-cz-col">
                <div className="ard-cz-head">
                    <span>Zone Score</span>
                    <span>Zone</span>
                    <span>Actions</span>
                </div>
                <div className="ard-cz-row">
                    <span className="ard-score-box">{score?.zone_score ?? "-"}</span>
                    <span>{orDash(score?.zone_name)}</span>
                    <button
                        type="button"
                        className="ard-icon-btn"
                        disabled
                        title="Edit (not wired up yet)"
                        aria-label="Edit zone"
                    >
                        <i className="fa-solid fa-pen" aria-hidden="true"></i>
                    </button>
                </div>
            </div>
        </div>
    </section>
);

export default ConfidentialityZone;
