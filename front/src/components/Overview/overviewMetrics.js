/**
 * Turns the four module payloads into the numbers the dashboard cards show.
 *
 * Kept out of the components so the mapping from backend field to card is in
 * one readable place — several cards combine two modules, and a few need a
 * derivation rather than a plain field read.
 */

/** Zones the seed defines as reachable from outside the organisation.
 *  See DEFAULT_ZONES in app/modules/risk/seed.py.
 *
 *  Matched on a normalised key (lowercased, spaces around the slash removed)
 *  because the seeded name is "Internet / Public" while operator-created zones
 *  spell it "Internet/Public". Comparing the raw strings missed the seeded
 *  zone entirely, so its assets never counted as internet-exposed. */
const EXPOSED_ZONES = new Set(["internet/public", "dmz"]);

const zoneKey = (name) =>
    String(name || "").toLowerCase().replace(/\s*\/\s*/g, "/").trim();

const round = (value) =>
    typeof value === "number" && Number.isFinite(value)
        ? Math.round(value)
        : null;

/** Count of assets sitting in an internet-facing zone. */
export const exposedAssets = (riskSummary) => {
    const zones = riskSummary?.by_zone;
    if (!Array.isArray(zones)) return null;
    return zones
        .filter((z) => EXPOSED_ZONES.has(zoneKey(z.zone_name)))
        .reduce((sum, z) => sum + (z.count || 0), 0);
};

/**
 * Assets whose *calculated* risk level is critical.
 *
 * Reads by_risk_level from /api/risk/summary — the aggregate over
 * asset_risk_scores.risk_level — not the operator's own classification in
 * asset_inventory.risk_level. The two are easy to confuse (both columns are
 * called "risk level"), but only the calculated band answers "is this asset
 * actually in a critical state?": the manual classification is one of six
 * inputs and carries 20% of the weight, so an asset marked critical that sits
 * in a safe zone with no open ports and a clean audit is not a critical risk.
 *
 * A 0 here is a real answer, not a missing one — it means nothing scored >= 81.
 */
export const criticalRisks = (riskSummary) => {
    const levels = riskSummary?.by_risk_level;
    if (!Array.isArray(levels)) return null;
    const critical = levels.find((l) => l.level === "critical");
    return critical ? critical.count : 0;
};

export const totalAssets = (riskSummary) =>
    riskSummary?.totals?.total_assets ?? null;

/**
 * The dashboard reports RISK, where a higher number is worse.
 *
 * /api/dashboard/security-score returns the opposite: a *health* score, with
 * every sub-score inverted (100 - avg_risk) and bands running 90+ excellent ..
 * <40 critical. Flip it once here so the headline tile and the gauge show the
 * same risk number, and nothing has to reason about which direction a given
 * value is in.
 */
export const riskFromSecurityScore = (securityScore) => {
    const value = round(securityScore);
    return value === null ? null : 100 - value;
};

export const complianceScore = (auditOverview) =>
    round(auditOverview?.average_compliance);

export const hardeningScore = (hardeningOverview) =>
    round(hardeningOverview?.hardening_score);

/**
 * Labels for the breakdown rows, keyed by the sub_scores keys the backend
 * returns. "vulnerability" is not in the Figma mock but the endpoint computes
 * it, so it is shown rather than silently dropped.
 */
export const SUB_SCORE_LABELS = {
    asset_health: "Asset Health",
    audit_compliance: "Audit Compliance",
    hardening: "Hardening",
    risk_intelligence: "Risk Intelligence",
    exposure_intelligence: "Exposure Intelligence",
    vulnerability: "Vulnerability",
};

/** sub_scores object -> ordered rows for the breakdown table.
 *  Currently unused: the "NGCorion Security Score Breakdown" panel was removed
 *  from the dashboard pending further development. Kept for when it returns. */
export const breakdownRows = (securityScore) => {
    const subs = securityScore?.sub_scores;
    if (!subs) return [];
    return Object.keys(SUB_SCORE_LABELS)
        .filter((key) => subs[key])
        .map((key) => ({
            key,
            label: SUB_SCORE_LABELS[key],
            score: round(subs[key].score),
            weight: subs[key].weight,
            incomplete: !!subs[key].incomplete,
        }));
};

/**
 * The four module tiles, each summarising one area and linking to its screen.
 *
 * The headline number is whatever that module leads with on its own dashboard,
 * so the two pages agree: asset count, average compliance, hardening success
 * rate, and the count of critical-risk assets.
 */
export const moduleCards = ({
    riskSummary,
    auditOverview,
    hardeningOverview,
}) => [
    {
        key: "assets",
        title: "Asset Management",
        value: totalAssets(riskSummary),
        unit: "Asset",
        to: "/assets",
    },
    {
        key: "auditing",
        title: "Auditing",
        value: complianceScore(auditOverview),
        unit: "Compliance",
        suffix: "%",
        to: "/audit",
    },
    {
        key: "hardening",
        title: "Hardening",
        value: hardeningScore(hardeningOverview),
        unit: "Hardened",
        suffix: "%",
        to: "/hardening/overview",
    },
    {
        key: "risk",
        title: "Risk Intelligence",
        value: criticalRisks(riskSummary),
        unit: "Critical Risk Assets",
        to: "/risk/overview",
    },
];

/** The six headline tiles across the top of the design. */
export const headlineMetrics = ({
    riskSummary,
    auditOverview,
    hardeningOverview,
    securityScore,
}) => [
    {
        // Risk, not health: higher is worse, matching the gauge below.
        key: "security_score",
        label: "Security Risk Score",
        value: riskFromSecurityScore(securityScore?.security_score),
        suffix: "/100",
    },
    {
        key: "total_assets",
        label: "Total Assets",
        value: totalAssets(riskSummary),
    },
    {
        // "Critical Risk Assets", not "Critical Risks": it counts assets whose
        // calculated level is critical, and the bare wording was read as the
        // Asset List classification of the same name.
        key: "critical_risks",
        label: "Critical Risk Assets",
        value: criticalRisks(riskSummary),
    },
    {
        key: "exposed_assets",
        label: "Internet Exposed Assets",
        value: exposedAssets(riskSummary),
    },
    {
        key: "compliance_score",
        label: "Compliance Score",
        value: complianceScore(auditOverview),
        suffix: "%",
    },
    {
        key: "hardening_score",
        label: "Hardening Score",
        value: hardeningScore(hardeningOverview),
        suffix: "%",
    },
];
