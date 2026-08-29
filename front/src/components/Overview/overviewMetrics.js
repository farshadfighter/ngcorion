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

/**
 * Assets an operator classified as critical in Asset List.
 *
 * This reads asset_inventory.risk_level (the classification shown in the Asset
 * List "Risk Level" column), NOT asset_risk_scores.risk_level (the calculated
 * band aggregated by /api/risk/summary). They are different columns: the
 * classification is one of the six inputs to the score, so an asset marked
 * critical can still score medium once zone, ports, audit and hardening are
 * weighed in. Reading the calculated band here showed 0 while the Asset List
 * plainly listed critical assets, which read as a bug.
 */
export const criticalRisks = (assetList) => {
    if (!Array.isArray(assetList)) return null;
    return assetList.filter(
        (a) => String(a?.risk_level || "").toLowerCase() === "critical"
    ).length;
};

export const totalAssets = (riskSummary) =>
    riskSummary?.totals?.total_assets ?? null;

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
    assetList,
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
        value: criticalRisks(assetList),
        unit: "Critical Risks",
        to: "/risk/overview",
    },
];

/** The six headline tiles across the top of the design. */
export const headlineMetrics = ({
    riskSummary,
    assetList,
    auditOverview,
    hardeningOverview,
    securityScore,
}) => [
    {
        key: "security_score",
        label: "Security Score",
        value: round(securityScore?.security_score),
        suffix: "/100",
    },
    {
        key: "total_assets",
        label: "Total Assets",
        value: totalAssets(riskSummary),
    },
    {
        key: "critical_risks",
        label: "Critical Risks",
        value: criticalRisks(assetList),
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
