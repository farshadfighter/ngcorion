import { describe, expect, it } from "vitest";
import {
    attentionItems,
    breakdownRows,
    changeTone,
    coverageRows,
    criticalRisks,
    exposedAssets,
    riskFromSecurityScore,
} from "./overviewMetrics";

describe("dashboard metrics", () => {
    it("shows the score as risk, higher is worse", () => {
        expect(riskFromSecurityScore(72.4)).toBe(28);
        expect(riskFromSecurityScore(null)).toBe(null);
    });

    it("turns the six sub-scores into risk rows with their pages, in a fixed order", () => {
        const rows = breakdownRows({
            sub_scores: {
                vulnerability: { score: 90, weight: 10, incomplete: false },
                asset_health: { score: 60, weight: 20, incomplete: true },
            },
        });
        expect(rows.map((r) => [r.key, r.risk, r.weight, r.incomplete, r.to])).toEqual([
            ["asset_health", 40, 20, true, "/assets"],
            ["vulnerability", 10, 10, false, "/cve"],
        ]);
        expect(breakdownRows(null)).toEqual([]);
    });

    it("keeps only the attention items it can name, above zero, in the backend's order", () => {
        const items = attentionItems({
            attention: [
                { key: "critical_alerts", count: 2, severity: "critical", link: "/alerts?severity=critical" },
                { key: "something_new", count: 5, severity: "high", link: "/x" },
                { key: "overdue_remediation", count: 0, severity: "high", link: "/remediation?view=overdue" },
                { key: "eol_unsupported", count: 6, severity: "high", link: "/assets/software/lifecycle" },
            ],
        });
        expect(items.map((i) => i.key)).toEqual(["critical_alerts", "eol_unsupported"]);
        expect(items[0].label).toBeTruthy();
    });

    it("gives coverage a share, and none when there is nothing to cover", () => {
        const rows = coverageRows({
            coverage: [
                { key: "audited", covered: 3, total: 8, link: "/audit/sessions" },
                { key: "backed_up", covered: 0, total: 0, link: "/backup/overview" },
            ],
        });
        expect(rows.map((r) => r.pct)).toEqual([38, null]);
    });

    it("reads a 30-day change by direction: a rise in risk is bad, in compliance good", () => {
        expect(changeTone(5, false)).toEqual({ dir: "up", good: false });
        expect(changeTone(-5, false)).toEqual({ dir: "down", good: true });
        expect(changeTone(4, true)).toEqual({ dir: "up", good: true });
        expect(changeTone(0.2, true)).toEqual({ dir: "flat", good: null });
        expect(changeTone(null, true)).toBe(null);
    });

    it("counts critical and internet-exposed assets from the risk summary", () => {
        const summary = {
            by_risk_level: [{ level: "critical", count: 4 }],
            by_zone: [{ zone_name: "Internet / Public", count: 2 }, { zone_name: "DMZ", count: 3 }, { zone_name: "Core", count: 9 }],
        };
        expect(criticalRisks(summary)).toBe(4);
        expect(exposedAssets(summary)).toBe(5);
        expect(criticalRisks({ by_risk_level: [] })).toBe(0);
        expect(exposedAssets(null)).toBe(null);
    });
});
