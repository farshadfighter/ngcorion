import { describe, expect, it, vi, afterEach } from "vitest";
import { duration, parseUtc, relativeDays } from "./dates.js";

describe("parseUtc", () => {
    it("reads the API's naive timestamps as UTC", () => {
        expect(parseUtc("2026-10-01T02:00:00").toISOString()).toBe("2026-10-01T02:00:00.000Z");
    });
    it("keeps an explicit zone", () => {
        expect(parseUtc("2026-10-01T02:00:00+03:30").toISOString()).toBe("2026-09-30T22:30:00.000Z");
        expect(parseUtc("2026-10-01T02:00:00Z").toISOString()).toBe("2026-10-01T02:00:00.000Z");
    });
    it("is null for nothing or garbage", () => {
        expect(parseUtc(null)).toBeNull();
        expect(parseUtc("not a date")).toBeNull();
    });
});

describe("relativeDays", () => {
    afterEach(() => vi.useRealTimers());
    it("counts whole days", () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2026-10-10T12:00:00Z"));
        expect(relativeDays("2026-10-10T08:00:00")).toBe("Today");
        expect(relativeDays("2026-10-09T08:00:00")).toBe("Yesterday");
        expect(relativeDays("2026-09-30T08:00:00")).toBe("10 days ago");
        expect(relativeDays(null)).toBe("—");
    });
});

describe("duration", () => {
    it("formats seconds, minutes and hours", () => {
        expect(duration("2026-10-01T02:00:00", "2026-10-01T02:00:20")).toBe("20 s");
        expect(duration("2026-10-01T02:00:00", "2026-10-01T02:13:00")).toBe("13 min");
        expect(duration("2026-10-01T02:00:00", "2026-10-01T03:05:00")).toBe("1 h 05 min");
        expect(duration("2026-10-01T02:00:00", null)).toBeNull();
    });
});
