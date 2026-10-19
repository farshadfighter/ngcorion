import { t } from "../../i18n";
/**
 * Turns the dashboard's payloads into what its sections show.
 *
 * GET /api/dashboard/overview (app/modules/dashboard/overview.py) carries the "needs action" counts,
 * coverage, the 90-day trends and the riskiest assets, each part filled only from the modules the user
 * may read; /api/dashboard/security-score and /api/risk/summary carry the score and the risk counts.
 * Kept out of the components so the mapping from backend key to label and page is in one place.
 */

/** Zones the seed defines as reachable from outside the organisation.
 *  See DEFAULT_ZONES in app/modules/risk/seed.py.
 *
 *  Matched on a normalised key (lowercased, spaces around the slash removed)
 *  because the seeded name is "Internet / Public" while operator-created zones
 *  spell it "Internet/Public". */
const EXPOSED_ZONES = new Set(["internet/public", "dmz"]);

const zoneKey = (name) =>
    String(name || "").toLowerCase().replace(/\s*\/\s*/g, "/").trim();

/** A value that is there (0 is a value). */
export const hasValue = (v) => v !== null && v !== undefined;

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
 * Assets whose *calculated* risk level is critical (asset_risk_scores.risk_level), not the operator's
 * own classification in the asset list. A 0 is a real answer: nothing scored 81 or more.
 */
export const criticalRisks = (riskSummary) => {
    const levels = riskSummary?.by_risk_level;
    if (!Array.isArray(levels)) return null;
    const critical = levels.find((l) => l.level === "critical");
    return critical ? critical.count : 0;
};

/**
 * The dashboard reports RISK, where a higher number is worse.
 *
 * /api/dashboard/security-score returns the opposite: a *health* score, with every sub-score inverted
 * (100 - avg_risk). Flip it once here so the score and its parts all read the same way.
 */
export const riskFromSecurityScore = (securityScore) => {
    const value = round(securityScore);
    return value === null ? null : 100 - value;
};

/** The six parts of the score, each with the page that explains it. */
export const SUB_SCORES = [
    { key: "asset_health", label: t("Asset Health"), to: "/assets" },
    { key: "audit_compliance", label: t("Audit Compliance"), to: "/audit" },
    { key: "hardening", label: t("Hardening"), to: "/hardening/overview" },
    { key: "risk_intelligence", label: t("Risk Intelligence"), to: "/risk/overview" },
    { key: "exposure_intelligence", label: t("Exposure Intelligence"), to: "/risk/exposure" },
    { key: "vulnerability", label: t("Vulnerability"), to: "/cve" },
];

/** sub_scores -> rows of the breakdown, as risk (higher is worse), each with its weight and page. */
export const breakdownRows = (securityScore) => {
    const subs = securityScore?.sub_scores;
    if (!subs) return [];
    return SUB_SCORES.filter((s) => subs[s.key]).map((s) => ({
        ...s,
        risk: riskFromSecurityScore(subs[s.key].score),
        weight: subs[s.key].weight,
        incomplete: !!subs[s.key].incomplete,
    }));
};

/** What each "needs action" count means (the backend's keys). */
export const ATTENTION_LABELS = {
    kev_assets: t("Assets with exploited vulnerabilities (KEV)"),
    critical_alerts: t("Critical alerts not acknowledged"),
    devices_down: t("Monitored devices not answering"),
    system_backup_failed: t("Last backup of NGCorion failed"),
    overdue_remediation: t("Overdue remediation items"),
    certificates_expired: t("Expired certificates"),
    certificates_expiring: t("Certificates expiring within 30 days"),
    eol_unsupported: t("Assets on unsupported software (end of life)"),
    external_changes: t("Devices changed outside NGCorion this week"),
    failed_jobs_discovery: t("Scheduled discoveries that failed"),
    failed_jobs_audit: t("Scheduled audits that failed"),
    failed_jobs_backup: t("Scheduled backups that failed"),
    acceptances_pending: t("Risk acceptances waiting for your approval"),
    policy_pending: t("Benchmark policy rules waiting for your approval"),
};

/** Items the page knows how to name, in the backend's order (most urgent first). */
export const attentionItems = (overview) =>
    (overview?.attention || []).filter((i) => ATTENTION_LABELS[i.key] && i.count > 0)
        .map((i) => ({ ...i, label: ATTENTION_LABELS[i.key] }));

export const COVERAGE_LABELS = {
    audited: { label: t("Audited in the last 90 days"), unit: t("of all assets") },
    backed_up: { label: t("Configuration backed up in the last 30 days"), unit: t("of the devices that can be backed up") },
    monitored: { label: t("Monitored over SNMP"), unit: t("of all assets") },
    eol_known: { label: t("End-of-life status known"), unit: t("of all assets") },
};

/** Coverage rows with their share; a module with nothing to cover shows no share, not 0%. */
export const coverageRows = (overview) =>
    (overview?.coverage || []).filter((c) => COVERAGE_LABELS[c.key]).map((c) => ({
        ...c,
        ...COVERAGE_LABELS[c.key],
        pct: c.total ? Math.round((100 * c.covered) / c.total) : null,
    }));

/** Risk factors, as the backend names them (app/modules/dashboard/overview.py FACTORS). */
export const FACTOR_LABELS = {
    criticality: t("Criticality"),
    asset_risk: t("Asset Risk"),
    zone: t("Zone"),
    open_ports: t("Open Ports"),
    audit: t("Audit Risk"),
    hardening: t("Hardening"),
    vulnerability: t("Vulnerability"),
};

/**
 * How a 30-day change reads: for risk a rise is bad, for compliance a fall is.
 * {dir: "up" | "down" | "flat", good: true | false | null}, or null without a change.
 */
export const changeTone = (change, higherIsBetter) => {
    if (change === null || change === undefined) return null;
    if (Math.abs(change) < 0.5) return { dir: "flat", good: null };
    const dir = change > 0 ? "up" : "down";
    return { dir, good: (dir === "up") === higherIsBetter };
};
