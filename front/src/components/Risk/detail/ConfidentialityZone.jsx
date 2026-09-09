import React from "react";

import { orDash, titleCase, badgeForScore } from "../riskConstants";

/**
 * "Criticality, Confidentiality & Zone": the three asset-derived inputs to the
 * risk score, shown read-only.
 *
 * Spec section 3.1 has these come from Asset Management, and the calculation
 * service already reads them from the asset (see service.py::_criticality_level
 * and ::_zone — the asset's confidentiality_level and asset_role). They are
 * edited in Asset List and only reported here, so this screen has no pencils:
 * one place to set a value, one place to read it.
 *
 * Confidentiality is the asset field that feeds Criticality (AC); Risk Level is
 * the asset field that feeds Asset Risk (AR), the 20%-weighted factor that
 * previously had nowhere on this page at all.
 */
/* Each box holds a raw 0-100 component score, so its colour comes from the band
   that score falls in (badgeForScore) rather than the asset's overall level —
   a Zone scoring 80 is "high" even when the asset as a whole lands elsewhere. */
const ScoreBox = ({ score }) => {
    const colors = badgeForScore(score);
    return (
        <span
            className="ard-score-box"
            style={colors ? { background: colors.bg, color: colors.fg } : undefined}
        >
            {score ?? "-"}
        </span>
    );
};

const Cell = ({ heading, score, label }) => (
    <div className="ard-cz-col">
        <div className="ard-cz-head">
            <span>{heading} Score</span>
            <span>{heading}</span>
        </div>
        <div className="ard-cz-row">
            <ScoreBox score={score} />
            <span>{label ? titleCase(label) : "-"}</span>
        </div>
    </div>
);

export const ConfidentialityZone = ({ asset, score }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">Criticality, Confidentiality &amp; Zone</h3>
        <div className="ard-cz-grid">
            <Cell
                heading="Criticality"
                score={score?.criticality_score}
                label={score?.criticality_level}
            />
            {/* AR — the asset's own risk level, 20% of the score. Its weighted
                value is asset_risk_score; the raw classification is the label. */}
            <Cell
                heading="Asset Risk"
                score={score?.asset_risk_score}
                label={score?.asset_risk_level || asset?.risk_level}
            />
            <div className="ard-cz-col">
                <div className="ard-cz-head">
                    <span>Zone Score</span>
                    <span>Zone</span>
                </div>
                <div className="ard-cz-row">
                    <ScoreBox score={score?.zone_score} />
                    <span>{orDash(score?.zone_name)}</span>
                </div>
            </div>
        </div>

        {asset?.confidentiality_level && (
            <p className="ard-cz-sub">
                Confidentiality: {titleCase(asset.confidentiality_level)}
            </p>
        )}

        <p className="ard-cz-sub">
            These values come from Asset List and are not editable here.
        </p>
    </section>
);

export default ConfidentialityZone;
