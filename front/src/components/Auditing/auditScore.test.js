import { describe, expect, it } from "vitest";
import { auditScore } from "./auditScore.js";

describe("auditScore", () => {
    it("shows the session's score over the scored checks, adding up to 100", () => {
        // a Linux audit: 174 rows, total_checks the module's scored ones, passed/failed every row
        const compliance = { total_checks: 150, passed: 93, failed: 81, compliance_pct: 62.4, results: 174,
                             scored: 150, scored_passed: 94, scored_failed: 56, not_scored: 24 };
        const s = auditScore(compliance, []);
        expect(s.conformity).toBe(62);
        expect(s.nonConformity).toBe(38);
        expect([s.passed, s.failed, s.scored, s.total, s.notScored]).toEqual([94, 56, 150, 174, 24]);
    });

    it("works from the rows with an older server: not applicable, info and policy rows left out", () => {
        const rows = [
            { status: "pass" }, { status: "fail" }, { status: "fail" },
            { status: "fail", level: "INFO" }, { status: "not_applicable" }, { status: "error" },
            { status: "fail", policy: "excluded" },
        ];
        const s = auditScore({ total_checks: 3, passed: 1, failed: 4 }, rows);
        expect([s.passed, s.failed, s.scored, s.total, s.notScored]).toEqual([1, 2, 3, 7, 4]);
        expect([s.conformity, s.nonConformity]).toEqual([33, 67]);
        expect(s.failedRows).toBe(4);                          // hardening still sees every failed row
    });

    it("nothing scored: no percentages", () => {
        const s = auditScore({ scored: 0, scored_passed: 0, scored_failed: 0, results: 2, compliance_pct: 0 }, []);
        expect([s.conformity, s.nonConformity, s.notScored]).toEqual([0, 0, 2]);
    });
});
