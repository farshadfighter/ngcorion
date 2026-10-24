import { describe, expect, it } from "vitest";
import { countByDomain, evidenceText, groupByRule } from "./architectureFormat.js";

const rules = [
    { code: "AV-101", title: "Reachable from the Internet without a firewall", severity: "high", category: "segmentation" },
    { code: "AV-134", title: "Network device with a single uplink", severity: "low", category: "availability" },
];

describe("architecture findings", () => {
    it("groups by check, most severe first, assets by name", () => {
        const groups = groupByRule([
            { id: 1, rule_code: "AV-134", asset_name: "sw-2", status: "open", category: "availability" },
            { id: 2, rule_code: "AV-101", asset_name: "web-02", status: "open", category: "segmentation" },
            { id: 3, rule_code: "AV-101", asset_name: "db-01", status: "open", category: "segmentation" },
            { id: 4, rule_code: "AV-021", title: "Asset has never been audited", severity: "medium", asset_name: "x" },
        ], rules);
        expect(groups.map((g) => g.rule.code)).toEqual(["AV-101", "AV-021", "AV-134"]);
        expect(groups[0].findings.map((f) => f.asset_name)).toEqual(["db-01", "web-02"]);
        expect(groups[1].rule.title).toBe("Asset has never been audited");
    });

    it("counts open findings per SAFE domain", () => {
        expect(countByDomain([
            { status: "open", category: "segmentation" }, { status: "open", category: "segmentation" },
            { status: "accepted", category: "availability" }, { status: "open", category: "visibility" },
        ])).toEqual({ segmentation: 2, threat_defense: 0, management: 0, availability: 0, visibility: 1 });
    });

    it("draws a path with arrows", () => {
        expect(evidenceText("isp -> core-sw -> db-03")).toBe("isp → core-sw → db-03");
        expect(evidenceText(null)).toBe("");
    });
});
