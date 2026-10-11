/**
 * Tests: the Jalali calendar matches ICU (Intl "persian" calendar) day for day, and typed dates parse.
 */
import { describe, expect, it } from "vitest";
import {
    formatJalali, isoToJalali, jalaliMonthLength, jalaliToIso, parseJalali, persianWeekday, toPersianDigits,
} from "./jalali.js";

const icu = new Intl.DateTimeFormat("en-US-u-ca-persian-nu-latn", {
    year: "numeric", month: "numeric", day: "numeric", timeZone: "UTC",
});
const icuJalali = (date) => {
    const parts = Object.fromEntries(icu.formatToParts(date).map((p) => [p.type, p.value]));
    return { jy: parseInt(parts.year, 10), jm: Number(parts.month), jd: Number(parts.day) };
};

describe("Jalali calendar", () => {
    it("agrees with ICU on every day from 1950 to 2060, both ways", () => {
        const start = Date.UTC(1950, 0, 1);
        const end = Date.UTC(2060, 11, 31);
        for (let t = start; t <= end; t += 86400000) {
            const date = new Date(t);
            const iso = date.toISOString().slice(0, 10);
            const expected = icuJalali(date);
            const got = isoToJalali(iso);
            if (got.jy !== expected.jy || got.jm !== expected.jm || got.jd !== expected.jd) {
                throw new Error(`${iso}: got ${JSON.stringify(got)}, ICU says ${JSON.stringify(expected)}`);
            }
            if (jalaliToIso(got.jy, got.jm, got.jd) !== iso) throw new Error(`${iso} does not round-trip`);
            // Saturday is the first day of the Persian week
            if (persianWeekday(iso) !== (date.getUTCDay() + 1) % 7) throw new Error(`${iso}: wrong weekday`);
        }
    });

    it("knows the known dates", () => {
        expect(isoToJalali("2026-10-11")).toEqual({ jy: 1405, jm: 7, jd: 19 });
        expect(isoToJalali("2025-03-21")).toEqual({ jy: 1404, jm: 1, jd: 1 });
        expect(jalaliToIso(1403, 12, 30)).toBe("2025-03-20"); // 1403 is leap
        expect(jalaliToIso(1404, 12, 30)).toBeNull(); // 1404 is not
        expect(jalaliMonthLength(1405, 1)).toBe(31);
        expect(jalaliMonthLength(1405, 7)).toBe(30);
    });

    it("formats and parses what people type", () => {
        expect(formatJalali("2026-10-11")).toBe("۱۴۰۵/۰۷/۱۹");
        expect(parseJalali("۱۴۰۵/۷/۱۹")).toBe("2026-10-11");
        expect(parseJalali("1405-07-19")).toBe("2026-10-11");
        expect(parseJalali("١٤٠٥.٠٧.١٩")).toBe("2026-10-11");
        expect(parseJalali("")).toBe("");
        expect(parseJalali("1405/13/01")).toBeNull();
        expect(parseJalali("1405/07/31")).toBeNull();
        expect(parseJalali("tomorrow")).toBeNull();
        expect(toPersianDigits("12:05")).toBe("۱۲:۰۵");
    });
});
