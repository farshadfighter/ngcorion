import React from "react";

/**
 * "Hardening Impact": three before/after comparisons, each with a progress bar.
 * Figma: 12px track rx=6 (#DBDBDB) with a #14213D fill at 90% opacity.
 *
 * The "prior to hardening" figures have no backend source — asset_risk_history
 * records score changes but nothing marks which row predates hardening — so the
 * right-hand column and the bars render as pending. See
 * RISK_FRONTEND_BACKEND_REQUIREMENTS.md.
 */
const Row = ({ label, value, priorLabel, priorValue }) => {
    const hasPrior = priorValue !== null && priorValue !== undefined;
    const ratio =
        hasPrior && Number(priorValue) > 0
            ? Math.min(100, (Number(value) / Number(priorValue)) * 100)
            : 0;

    return (
        <div className="ard-impact-row">
            <div className="ard-impact-cols">
                <div className="ard-impact-box">
                    <span className="ard-impact-label">{label}</span>
                    <span className="ard-impact-value">
                        {value === null || value === undefined ? "-" : value}
                    </span>
                </div>
                <div className="ard-impact-prior">
                    <span className="ard-impact-label">{priorLabel}</span>
                    <span className="ard-impact-value ard-cell-pending">
                        {hasPrior ? priorValue : "—"}
                    </span>
                </div>
            </div>
            <div className="ard-progress" role="presentation">
                <div className="ard-progress-fill" style={{ width: `${ratio}%` }} />
            </div>
        </div>
    );
};

export const HardeningImpact = ({ score, auditSummary }) => (
    <section className="ard-card">
        <h3 className="ard-card-title">Hardening Impact</h3>

        <Row
            label="Number of Fixed Findings"
            value={
                auditSummary?.resolved_by_hardening ??
                score?.resolved_by_hardening_count ??
                null
            }
            priorLabel="Number of Findings prior to Hardening"
            priorValue={null}
        />
        <Row
            label="Current Audit Risk"
            value={score?.audit_risk_score ?? null}
            priorLabel="Audit Risk Prior to Hardening"
            priorValue={null}
        />
        <Row
            label="Current Risk Score"
            value={score?.final_risk_score ?? null}
            priorLabel="Risk Score Before Hardening"
            priorValue={null}
        />

        <p className="ard-notice ard-notice-inline">
            Before/after comparison needs a backend field marking the pre-hardening
            baseline — see the requirements doc.
        </p>
    </section>
);

export default HardeningImpact;
