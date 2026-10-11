/**
 * Tests: generated temporary passwords always pass the password policy, and the policy check
 * names what is missing.
 */
import { describe, expect, it } from "vitest";
import { generatePassword, policyProblems } from "./passwordTools.js";

describe("temporary passwords", () => {
    it("are 16 characters that meet the policy, and differ each time", () => {
        const seen = new Set();
        for (let i = 0; i < 500; i += 1) {
            const p = generatePassword();
            expect(p).toHaveLength(16);
            expect(policyProblems(p)).toEqual([]);
            seen.add(p);
        }
        expect(seen.size).toBe(500);
    });
    it("lists what a weak password lacks", () => {
        expect(policyProblems("abc")).toHaveLength(4);
        expect(policyProblems("Abcdefg1!")).toEqual([]);
    });
});
