/**
 * Architecture Validation (the topology against Cisco SAFE): names of the SAFE domains and places in the
 * network, and the findings grouped by the check that found them.
 */
import { t } from "../../i18n";

export const DOMAINS = [
    ["segmentation", t("Segmentation")],
    ["threat_defense", t("Threat defense")],
    ["management", t("Management")],
    ["availability", t("Availability")],
    ["visibility", t("Visibility")],
];
export const DOMAIN_LABEL = Object.fromEntries(DOMAINS);

export const PLACES = [
    ["internet", t("Internet")],
    ["edge", t("Edge (DMZ)")],
    ["data_center", t("Data center")],
    ["storage", t("Storage network (SAN)")],
    ["campus", t("Campus (users)")],
    ["branch", t("Branch")],
    ["wan", t("WAN")],
    ["cloud", t("Cloud")],
    ["guest", t("Guest network")],
    ["management", t("Management network")],
    ["lab", t("Lab")],
];
export const PLACE_LABEL = Object.fromEntries(PLACES);

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

/** Findings grouped by their check, most severe first: [{ rule, findings }]. A finding of a check the
 *  rule list does not have (an older one) still gets a group, from its own title. */
export function groupByRule(findings, rules) {
    const byCode = Object.fromEntries((rules || []).map((r) => [r.code, r]));
    const groups = new Map();
    for (const f of findings || []) {
        if (!groups.has(f.rule_code)) {
            groups.set(f.rule_code, {
                rule: byCode[f.rule_code] || {
                    code: f.rule_code, title: f.title, severity: f.severity, category: f.category,
                    recommendation: f.recommendation,
                },
                findings: [],
            });
        }
        groups.get(f.rule_code).findings.push(f);
    }
    return [...groups.values()]
        .map((g) => ({ ...g, findings: [...g.findings].sort((a, b) => (a.asset_name || "").localeCompare(b.asset_name || "")) }))
        .sort((a, b) => (SEVERITY_ORDER[a.rule.severity] ?? 3) - (SEVERITY_ORDER[b.rule.severity] ?? 3)
            || a.rule.code.localeCompare(b.rule.code));
}

/** Open findings per SAFE domain. */
export function countByDomain(findings) {
    const out = Object.fromEntries(DOMAINS.map(([key]) => [key, 0]));
    for (const f of findings || []) {
        if (f.status === "open" && f.category in out) out[f.category] += 1;
    }
    return out;
}

/** A path "a -> b -> c" drawn with arrows. */
export function evidenceText(evidence) {
    return evidence ? String(evidence).replaceAll(" -> ", " → ") : "";
}
