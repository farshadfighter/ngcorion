/**
 * Tests: the time zone list leads with Tehran, shows a readable name and the UTC offset, and finds a
 * zone by Persian or English words or by its offset.
 */
import { describe, expect, it } from "vitest";
import { DEFAULT_TIMEZONE, TIMEZONES, filterZones, utcOffset, zoneOptions } from "./timezones.js";

const at = new Date("2026-01-15T12:00:00Z");     // a winter date: no daylight saving anywhere north

describe("time zones", () => {
    it("lists Tehran first, then UTC", () => {
        expect(TIMEZONES[0]).toBe(DEFAULT_TIMEZONE);
        const options = zoneOptions("en", TIMEZONES, at);
        expect(options.slice(0, 2).map((o) => o.value)).toEqual(["Asia/Tehran", "UTC"]);
        expect(new Set(options.map((o) => o.value)).size).toBe(options.length);
    });

    it("computes the offset", () => {
        expect(utcOffset("Asia/Tehran", at)).toBe("+03:30");
        expect(utcOffset("UTC", at)).toBe("+00:00");
        expect(utcOffset("America/New_York", at)).toBe("-05:00");
        expect(utcOffset("Asia/Kolkata", at)).toBe("+05:30");
    });

    it("labels a zone with its name and offset, in Persian digits in Persian", () => {
        const en = zoneOptions("en", ["Asia/Tehran"], at)[0].label;
        expect(en).toContain("Iran");
        expect(en).toContain("Asia/Tehran");
        expect(en).toContain("UTC+03:30");
        const fa = zoneOptions("fa", ["Asia/Tehran"], at)[0].label;
        expect(fa).toContain("ایران");
        expect(fa).toContain("Asia/Tehran");
        expect(fa).toContain("UTC+۰۳:۳۰");
    });

    it("finds Tehran by Persian or English words, or by offset", () => {
        const fa = zoneOptions("fa", TIMEZONES, at);
        const en = zoneOptions("en", TIMEZONES, at);
        for (const [options, query] of [[fa, "تهران"], [fa, "ایران"], [fa, "يران"], [en, "iran"],
                                        [en, "TEHRAN"], [en, "+03:30"], [fa, "۰۳:۳۰"]]) {
            const found = filterZones(options, query).map((o) => o.value);
            expect(found, query).toContain("Asia/Tehran");
        }
        expect(filterZones(en, "")).toHaveLength(en.length);
        expect(filterZones(en, "no such place")).toHaveLength(0);
        expect(filterZones(en, "new york").map((o) => o.value)).toEqual(["America/New_York"]);
    });
});
