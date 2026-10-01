// Dates as the API sends them: naive UTC timestamps ("2026-10-01T02:00:00").
// Shown in the user's language: Solar Hijri with Persian digits in Persian,
// Gregorian in English (see uiLocale in ../i18n).
import { t, uiLocale, currentLanguage } from "../i18n";

export function parseUtc(value) {
    if (!value) return null;
    const s = String(value);
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) || s.length <= 10 ? s : `${s}Z`);
    return Number.isNaN(d.getTime()) ? null : d;
}

const pad = (n) => String(n).padStart(2, "0");

/** "10:26" in the language's digits. */
export function formatTime(d) {
    return d.toLocaleTimeString(uiLocale(), { hour: "2-digit", minute: "2-digit", hour12: false });
}

export function formatWhen(value) {
    const d = parseUtc(value);
    if (!d) return "—";
    const now = new Date();
    const time = formatTime(d);
    const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const diff = Math.round((today - day) / 86400000);
    if (diff === 0) return t("Today {{time}}", { time });
    if (diff === 1) return t("Yesterday {{time}}", { time });
    return `${d.toLocaleDateString(uiLocale(), { day: "numeric", month: "short", year: "numeric" })} ${time}`;
}

export function formatDate(value) {
    const d = parseUtc(value);
    return d ? d.toLocaleDateString(uiLocale(), { day: "numeric", month: "short", year: "numeric" }) : "—";
}

/** Date and time: "1 Oct 2026, 10:26" / "۹ مهر ۱۴۰۵، ۱۰:۲۶". */
export function formatDateTime(value) {
    const d = value instanceof Date ? value : parseUtc(value);
    if (!d) return "—";
    return d.toLocaleString(uiLocale(), { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

export function ageDays(value) {
    const d = parseUtc(value);
    return d ? (Date.now() - d.getTime()) / 86400000 : null;
}

/** "Today", "Yesterday", "12 days ago". */
export function relativeDays(value) {
    const days = ageDays(value);
    if (days == null) return "—";
    const n = Math.floor(days);
    return n <= 0 ? t("Today") : n === 1 ? t("Yesterday") : t("{{count}} days ago", { count: n });
}

/** Time between two timestamps: "20 s", "2 min", "1 h 05 min". */
export function duration(start, end) {
    const a = parseUtc(start), b = parseUtc(end);
    if (!a || !b) return null;
    const s = Math.max(0, Math.round((b - a) / 1000));
    if (s < 60) return t("{{s}} s", { s });
    const m = Math.round(s / 60);
    return m < 60 ? t("{{m}} min", { m }) : t("{{h}} h {{mm}} min", { h: Math.floor(m / 60), mm: pad(m % 60) });
}

/** Header date: "Thursday, October 1, 2026" / "پنجشنبه ۹ مهر ۱۴۰۵". */
export function formatLongDate(d) {
    const date = d instanceof Date ? d : parseUtc(d);
    if (!date) return "";
    const opts = { weekday: "long", year: "numeric", month: "long", day: "numeric" };
    if (currentLanguage() !== "fa") return date.toLocaleDateString(uiLocale(), opts);
    // ICU orders the Persian parts year-first; write them the way Persian reads.
    const part = Object.fromEntries(new Intl.DateTimeFormat(uiLocale(), opts).formatToParts(date).map((p) => [p.type, p.value]));
    return `${part.weekday} ${part.day} ${part.month} ${part.year}`;
}
