import { describe, expect, it } from "vitest";
import { versionCompare } from "./cveFormat.js";

describe("versionCompare", () => {
    it("orders package versions the way the distributions do", () => {
        expect(versionCompare("3.0.13-0ubuntu3.9", "3.0.13-0ubuntu3.15")).toBe(-1);
        expect(versionCompare("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.6")).toBe(1);
        expect(versionCompare("1.0~rc1", "1.0")).toBe(-1);
        expect(versionCompare("8.7p1-38.el9_4.1", "8.7p1-38.el9_4.1")).toBe(0);
        expect(versionCompare(null, "1.0")).toBe(-1);
    });
});
