import { describe, expect, it } from "vitest";
import { usagePct, usageTone } from "./storageFormat";

describe("storage usage", () => {
    it("is a share of the budget, one decimal, capped at 100", () => {
        expect(usagePct(512, 1024)).toBe(50);
        expect(usagePct(1, 3)).toBe(33.3);
        expect(usagePct(5, 4)).toBe(100);
        expect(usagePct(5, 0)).toBeNull();
    });
    it("turns amber at 70% and red at 90%", () => {
        expect([usageTone(10), usageTone(70), usageTone(95), usageTone(null)]).toEqual(["is-ok", "is-warn", "is-high", ""]);
    });
});
