import { describe, expect, it } from "vitest";
import { barWidths, impactDelta, impactRows } from "./hardeningImpact";

describe("Hardening Impact rows", () => {
    it("pairs each figure before and now, one decimal", () => {
        const rows = impactRows({ findings_before: 4, findings_now: 2, audit_risk_before: 100, audit_risk_now: 45.4545,
                                  risk_before: 61.25, risk_now: 52.04 });
        expect(rows.map((r) => [r.key, r.before, r.now])).toEqual([
            ["findings", 4, 2], ["audit", 100, 45.5], ["risk", 61.3, 52]]);
        expect(rows[2].missing).toBeNull();
    });
    it("says when no score predates the first change", () => {
        const risk = impactRows({ risk_before: null, risk_now: 40 })[2];
        expect(risk.before).toBeNull();
        expect(risk.missing).toBeTruthy();
    });
    it("gives the change and bars on one scale", () => {
        expect(impactDelta(100, 45.5)).toBe(-54.5);
        expect(impactDelta(null, 3)).toBeNull();
        expect(barWidths(4, 2)).toEqual([100, 50]);
        expect(barWidths(0, 0)).toEqual([0, 0]);
    });
});
