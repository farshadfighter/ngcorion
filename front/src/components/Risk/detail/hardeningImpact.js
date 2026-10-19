import { t } from "../../../i18n";

/**
 * The Hardening Impact rows of the risk detail (GET /api/risk/assets/{id} -> hardening_impact): each figure
 * just after the audit (or, for the risk score, before the first change) and now. Lower is better for all.
 */

const one = (v) => (v === null || v === undefined ? null : Math.round(Number(v) * 10) / 10);

export const impactRows = (impact) => [
    { key: "findings", label: t("Failed controls"), before: impact?.findings_before ?? null,
      now: impact?.findings_now ?? null },
    { key: "audit", label: t("Audit risk"), before: one(impact?.audit_risk_before), now: one(impact?.audit_risk_now) },
    { key: "risk", label: t("Risk score"), before: one(impact?.risk_before), now: one(impact?.risk_now),
      missing: impact?.risk_before == null ? t("No score was recorded before the first change.") : null,
      rose: t("The score also moves with everything else since then: new CVEs, open ports, the asset's profile.") },
];

/** now - before, one decimal; null when either is unknown. */
export const impactDelta = (before, now) =>
    before === null || before === undefined || now === null || now === undefined ? null : one(now - before);

/** Bar widths (0-100) of before and now on one scale, the larger of the two. */
export const barWidths = (before, now) => {
    const max = Math.max(Number(before) || 0, Number(now) || 0);
    if (!max) return [0, 0];
    return [((Number(before) || 0) / max) * 100, ((Number(now) || 0) / max) * 100];
};
