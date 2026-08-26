import React, { useState } from "react";

import { orDash, titleCase } from "../riskConstants";
import { usePermission } from "../../../hooks/usePermission";
import { EditRiskProfileModal } from "./EditRiskProfileModal";

/**
 * "Confidentiality & Zone" block: two score boxes with their labels, each with
 * a pencil that opens the edit dialog.
 *
 * The first column is labelled Criticality, not Confidentiality as in the Figma
 * mock: the score beside it is criticality_score, and criticality_level is what
 * PUT /api/risk/assets/{id}/profile actually sets. The asset's separate
 * confidentiality_level lives in Asset Management and is shown underneath so
 * nothing is lost.
 */
export const ConfidentialityZone = ({ asset, score, assetId }) => {
    const canWrite = usePermission("risk", "write");
    const [editing, setEditing] = useState(null); // "criticality" | "zone" | null

    const editTitle = canWrite
        ? "Edit"
        : "Editing requires risk write permission";

    return (
        <section className="ard-card">
            <h3 className="ard-card-title">Criticality &amp; Zone</h3>
            <div className="ard-cz-grid">
                <div className="ard-cz-col">
                    <div className="ard-cz-head">
                        <span>Criticality Score</span>
                        <span>Criticality</span>
                        <span>Actions</span>
                    </div>
                    <div className="ard-cz-row">
                        <span className="ard-score-box">
                            {score?.criticality_score ?? "-"}
                        </span>
                        <span>
                            {score?.criticality_level
                                ? titleCase(score.criticality_level)
                                : "-"}
                        </span>
                        <button
                            type="button"
                            className="ard-icon-btn"
                            onClick={() => setEditing("criticality")}
                            disabled={!canWrite}
                            title={editTitle}
                            aria-label="Edit criticality"
                        >
                            <i className="fa-solid fa-pen" aria-hidden="true"></i>
                        </button>
                    </div>
                    {/* A different field from criticality above: it comes from
                        Asset Management and is not part of the risk formula, so
                        it is labelled as such to stop it reading as an input. */}
                    {asset?.confidentiality_level && (
                        <p className="ard-cz-sub">
                            Confidentiality (from Asset List, not scored):{" "}
                            {titleCase(asset.confidentiality_level)}
                        </p>
                    )}
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
                            onClick={() => setEditing("zone")}
                            disabled={!canWrite}
                            title={editTitle}
                            aria-label="Edit zone"
                        >
                            <i className="fa-solid fa-pen" aria-hidden="true"></i>
                        </button>
                    </div>
                </div>
            </div>

            {editing && (
                <EditRiskProfileModal
                    assetId={assetId}
                    mode={editing}
                    current={{
                        criticalityLevel: score?.criticality_level,
                        zoneId: score?.zone_id,
                    }}
                    onClose={() => setEditing(null)}
                />
            )}
        </section>
    );
};

export default ConfidentialityZone;
