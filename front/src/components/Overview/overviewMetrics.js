/**
 * Turns the four module payloads into the numbers the dashboard cards show.
 *
 * Kept out of the components so the mapping from backend field to card is in
 * one readable place — several cards combine two modules, and a few need a
 * derivation rather than a plain field read.
 */

/** Zones the seed defines as reachable from outside the organisation.
 *  See DEFAULT_ZONES in app/modules/risk/seed.py. */
const EXPOSED_ZONES = ["Internet/Public", "DMZ"];

const round = (value) =>
    typeof value === "number" && Number.isFinite(value)
        ? Math.round(value)
        : null;

/** Count of assets sitting in an internet-facing zone. */
export const exposedAssets = (riskSummary) => {
    const zones = riskSummary?.by_zone;
    if (!Array.isArray(zones)) return null;
    return zones
        .filter((z) => EXPOSED_ZONES.includes(z.zone_name))
        .reduce((sum, z) => sum + (z.count || 0), 0);
};

/** Assets whose computed level is "critical". */
export const criticalRisks = (riskSummary) => {
    const levels = riskSummary?.by_risk_level;
    if (!Array.isArray(levels)) return null;
    const critical = levels.find((l) => l.level === "critical");
    return critical ? critical.count : 0;
};

export const totalAssets = (riskSummary) =>
    riskSummary?.totals?.total_assets ?? null;

export const complianceScore = (auditOverview) =>
    round(auditOverview?.average_compliance);

export const hardeningScore = (hardeningOverview) =>
    round(hardeningOverview?.hardening_score);

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
        unit: "Critical Risks",
        to: "/risk/overview",
    },
];

/**
 * The six headline tiles across the top of the design.
 *
 * `securityScore` has no endpoint — the overall score is a product decision
 * about weighting, not a query — so it is reported as pending rather than
 * invented here.
 */
export const headlineMetrics = ({
    riskSummary,
    auditOverview,
    hardeningOverview,
}) => [
    {
        key: "security_score",
        label: "Security Score",
        value: null,
        suffix: "/100",
        pending: true,
    },
    {
        key: "total_assets",
        label: "Total Assets",
        value: totalAssets(riskSummary),
    },
    {
        key: "critical_risks",
        label: "Critical Risks",
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
