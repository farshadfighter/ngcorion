/**
 * The Persian (Jalali, Solar Hijri) calendar for date fields: conversion to and from the ISO
 * dates ("2026-10-11") the API and <input type="date"> use, month lengths, and parsing what a
 * person types ("۱۴۰۵/۷/۱۹").
 *
 * Integer arithmetic on day numbers only (no Date, no time zone): the arithmetical Jalali calendar
 * with the 2820-year break table, the same one ICU uses for "fa-IR-u-ca-persian". The tests check
 * every day of 1950-2060 against Intl.
 */

const div = (a, b) => Math.trunc(a / b);
const mod = (a, b) => a - Math.trunc(a / b) * b;

// Years (Jalali) where the 33-year leap cycle restarts.
const BREAKS = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262,
    2324, 2394, 2456, 3178];

/** For a Jalali year: whether it is leap (0), the Gregorian year it starts in, and its 1 Farvardin in March. */
function jalCal(jy) {
    const gy = jy + 621;
    let leapJ = -14;
    let jp = BREAKS[0];
    let jump = 0;
    if (jy < jp || jy >= BREAKS[BREAKS.length - 1]) throw new RangeError(`Jalali year out of range: ${jy}`);
    for (let i = 1; i < BREAKS.length; i += 1) {
        const jm = BREAKS[i];
        jump = jm - jp;
        if (jy < jm) break;
        leapJ += div(jump, 33) * 8 + div(mod(jump, 33), 4);
        jp = jm;
    }
    let n = jy - jp;
    leapJ += div(n, 33) * 8 + div(mod(n, 33) + 3, 4);
    if (mod(jump, 33) === 4 && jump - n === 4) leapJ += 1;
    const leapG = div(gy, 4) - div((div(gy, 100) + 1) * 3, 4) - 150;
    const march = 20 + leapJ - leapG;
    if (jump - n < 6) n = n - jump + div(jump + 4, 33) * 33;
    let leap = mod(mod(n + 1, 33) - 1, 4);
    if (leap === -1) leap = 4;
    return { leap, gy, march };
}

/** Julian day number of a Gregorian date. */
function g2d(gy, gm, gd) {
    const d = div((gy + div(gm - 8, 6) + 100100) * 1461, 4) + div(153 * mod(gm + 9, 12) + 2, 5) + gd - 34840408;
    return d - div(div(gy + 100100 + div(gm - 8, 6), 100) * 3, 4) + 752;
}

/** Gregorian date of a Julian day number. */
function d2g(jdn) {
    let j = 4 * jdn + 139361631;
    j += div(div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908;
    const i = div(mod(j, 1461), 4) * 5 + 308;
    const gd = div(mod(i, 153), 5) + 1;
    const gm = mod(div(i, 153), 12) + 1;
    const gy = div(j, 1461) - 100100 + div(8 - gm, 6);
    return { gy, gm, gd };
}

function j2d(jy, jm, jd) {
    const r = jalCal(jy);
    return g2d(r.gy, 3, r.march) + (jm - 1) * 31 - div(jm, 7) * (jm - 7) + jd - 1;
}

function d2j(jdn) {
    const { gy } = d2g(jdn);
    let jy = gy - 621;
    const r = jalCal(jy);
    let k = jdn - g2d(gy, 3, r.march);
    if (k >= 0) {
        if (k <= 185) return { jy, jm: 1 + div(k, 31), jd: mod(k, 31) + 1 };
        k -= 186;
    } else {
        jy -= 1;
        k += 179;
        if (r.leap === 1) k += 1;
    }
    return { jy, jm: 7 + div(k, 30), jd: mod(k, 30) + 1 };
}

export const isLeapJalaliYear = (jy) => jalCal(jy).leap === 0;

/** Days in a Jalali month: 31 for the first six, 30 for the next five, 29 or 30 for Esfand. */
export const jalaliMonthLength = (jy, jm) => (jm <= 6 ? 31 : jm <= 11 ? 30 : isLeapJalaliYear(jy) ? 30 : 29);

const pad = (v, size = 2) => String(v).padStart(size, "0");

/** "2026-10-11" -> { jy: 1405, jm: 7, jd: 19 }; null for anything that is not an ISO date. */
export function isoToJalali(iso) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || "");
    if (!m) return null;
    const [gy, gm, gd] = [Number(m[1]), Number(m[2]), Number(m[3])];
    if (gm < 1 || gm > 12 || gd < 1 || gd > 31) return null;
    return d2j(g2d(gy, gm, gd));
}

/** { jy, jm, jd } -> "2026-10-11"; null for a day the month does not have. */
export function jalaliToIso(jy, jm, jd) {
    if (!Number.isInteger(jy) || !Number.isInteger(jm) || !Number.isInteger(jd)) return null;
    if (jy < 1 || jy > 3177 || jm < 1 || jm > 12 || jd < 1 || jd > jalaliMonthLength(jy, jm)) return null;
    const { gy, gm, gd } = d2g(j2d(jy, jm, jd));
    return `${pad(gy, 4)}-${pad(gm)}-${pad(gd)}`;
}

/** Weekday of an ISO date with Saturday as 0, the first day of the Persian week. */
export function persianWeekday(iso) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || "");
    if (!m) return null;
    // Julian day 0 was a Monday; Monday -> 2 in a week that starts on Saturday.
    return mod(g2d(Number(m[1]), Number(m[2]), Number(m[3])) + 2, 7);
}

/** Today's date where the browser is, as an ISO date. */
export function todayIso(now = new Date()) {
    return `${pad(now.getFullYear(), 4)}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

const PERSIAN_DIGITS = "۰۱۲۳۴۵۶۷۸۹";
const ARABIC_DIGITS = "٠١٢٣٤٥٦٧٨٩";

/** Persian and Arabic-Indic digits to ASCII ("۱۴۰۵" -> "1405"). */
export const toLatinDigits = (s) => String(s).replace(/[۰-۹٠-٩]/g, (c) => {
    const i = PERSIAN_DIGITS.indexOf(c);
    return String(i >= 0 ? i : ARABIC_DIGITS.indexOf(c));
});

/** ASCII digits to Persian ("1405" -> "۱۴۰۵"). */
export const toPersianDigits = (s) => String(s).replace(/\d/g, (c) => PERSIAN_DIGITS[Number(c)]);

/** "1405-07-19" style text for an ISO date in the Jalali calendar, Persian digits ("۱۴۰۵/۰۷/۱۹"). */
export function formatJalali(iso) {
    const j = isoToJalali(iso);
    return j ? toPersianDigits(`${j.jy}/${pad(j.jm)}/${pad(j.jd)}`) : "";
}

/**
 * What a person typed as a Jalali date -> ISO date. Accepts Persian, Arabic or Latin digits and
 * "/", "-", "." or spaces between year, month and day ("۱۴۰۵/۷/۱۹", "1405-07-19").
 * Returns "" for empty text and null for text that is not a date.
 */
export function parseJalali(text) {
    const s = toLatinDigits(text || "").trim();
    if (!s) return "";
    const m = /^(\d{4})\s*[/\-.\s]\s*(\d{1,2})\s*[/\-.\s]\s*(\d{1,2})$/.exec(s);
    if (!m) return null;
    return jalaliToIso(Number(m[1]), Number(m[2]), Number(m[3]));
}

export const JALALI_MONTHS = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان",
    "آذر", "دی", "بهمن", "اسفند"];
export const PERSIAN_WEEKDAYS = ["ش", "ی", "د", "س", "چ", "پ", "ج"];
export const PERSIAN_WEEKDAY_NAMES = ["شنبه", "یکشنبه", "دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه"];
