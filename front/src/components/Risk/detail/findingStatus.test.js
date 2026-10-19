import { describe, expect, it } from "vitest";
import { AUDIT_NOW, HARDENING, VERIFICATION, statusOf } from "./findingStatus";

describe("finding status labels", () => {
    it("names every status the findings endpoint sends", () => {
        for (const key of ["not_hardened", "previewed", "running", "applied", "failed"]) expect(HARDENING[key]).toBeTruthy();
        for (const key of ["verified", "awaiting_reaudit", "not_verified", "still_failing"]) expect(VERIFICATION[key]).toBeTruthy();
        expect(statusOf(AUDIT_NOW, "pass").tone).toBe("good");
    });
    it("shows nothing for no status, and an unknown one as it came", () => {
        expect(statusOf(VERIFICATION, null)).toBeNull();
        expect(statusOf(HARDENING, "queued")).toEqual({ label: "queued", tone: "neutral" });
    });
});
