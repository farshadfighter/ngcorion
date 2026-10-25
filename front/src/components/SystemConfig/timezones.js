/**
 * Time zones for the Time dialog: IANA names with a readable label and the UTC offset.
 *
 * Modern browsers can enumerate the full tz database themselves; the short list
 * is the fallback for those that cannot, and leads with the zones this product
 * is actually deployed in. The backend validates the name against
 * /usr/share/zoneinfo either way.
 *
 * A bare list of 418 names such as "Asia/Tehran" is hard to search, so each
 * option carries the zone's own name in the interface language ("وقت عادی
 * ایران", "Iran Standard Time") and its current UTC offset, and the search
 * matches either, the IANA name, or a few extra words (city, country) below.
 */
export const DEFAULT_TIMEZONE = "Asia/Tehran";

const FALLBACK = [
    "Asia/Tehran",
    "UTC",
    "Europe/London",
    "Europe/Berlin",
    "Europe/Moscow",
    "Asia/Dubai",
    "Asia/Baghdad",
    "Asia/Istanbul",
    "Asia/Kolkata",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "Australia/Sydney",
];

/** Words a person may type for a zone that its names do not contain. */
const ALIASES = {
    "Asia/Tehran": "تهران ایران iran tehran irst",
    "Asia/Dubai": "دبی امارات dubai uae",
    "Asia/Baghdad": "بغداد عراق iraq",
    "Asia/Istanbul": "استانبول ترکیه turkey",
    "Asia/Kabul": "کابل افغانستان afghanistan",
    "UTC": "گرینویچ utc gmt",
};

const supported =
    typeof Intl !== "undefined" && typeof Intl.supportedValuesOf === "function"
        ? (() => {
              try {
                  return Intl.supportedValuesOf("timeZone");
              } catch {
                  return null;
              }
          })()
        : null;

export const TIMEZONES =
    supported && supported.length
        ? // Keep Tehran at the top; UTC is not always in the browser's list.
          [DEFAULT_TIMEZONE, ...(supported.includes("UTC") ? [] : ["UTC"]),
           ...supported.filter((tz) => tz !== DEFAULT_TIMEZONE)]
        : FALLBACK;

function zonePart(locale, timeZone, style, date) {
    try {
        return new Intl.DateTimeFormat(locale, { timeZone, timeZoneName: style })
            .formatToParts(date)
            .find((p) => p.type === "timeZoneName")?.value;
    } catch {
        return undefined;
    }
}

/** Offset from UTC now, as "+HH:MM" ("+00:00" for UTC itself), from the browser's tz data. */
export function utcOffset(timeZone, date = new Date()) {
    const raw = zonePart("en-US", timeZone, "longOffset", date);     // "GMT+HH:MM", or "GMT" for UTC
    if (!raw) return "";
    const m = raw.match(/([+-])(\d{1,2})(?::?(\d{2}))?/);
    if (!m) return "+00:00";
    return `${m[1]}${m[2].padStart(2, "0")}:${m[3] || "00"}`;
}

const minutes = (offset) => {
    const m = offset.match(/([+-])(\d{2}):(\d{2})/);
    return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
};

const fold = (s) => String(s).toLowerCase().replace(/ي/g, "ی").replace(/ك/g, "ک").replace(/_/g, " ");

/**
 * The options for the dropdown: [{value, label, offset, search}], Tehran first, then UTC, then the
 * rest by offset and name. `language` is "fa" or "en"; offsets are in Persian digits in Persian.
 */
export function zoneOptions(language = "en", zones = TIMEZONES, date = new Date()) {
    const fa = language === "fa";
    const digits = (s) => (fa ? s.replace(/\d/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[d]) : s);
    const options = zones.map((value) => {
        const offset = utcOffset(value, date);
        const name = zonePart(fa ? "fa-IR" : "en-US", value, "longGeneric", date);
        const shown = `UTC${digits(offset)}`;
        // The IANA name stays as it is: it is what is saved and what the server shows.
        const label = name && name !== value ? `${name} · ${value} (${shown})` : `${value} (${shown})`;
        return {
            value, label, offset,
            search: fold(`${value} ${name || ""} ${ALIASES[value] || ""} utc${offset} ${shown}`),
        };
    });
    const rank = (o) => (o.value === DEFAULT_TIMEZONE ? 0 : o.value === "UTC" ? 1 : 2);
    return options.sort((a, b) => rank(a) - rank(b) || minutes(a.offset) - minutes(b.offset)
        || a.value.localeCompare(b.value));
}

/** Options whose label, IANA name or alias words contain every word of the query. */
export function filterZones(options, query) {
    const words = fold(query).trim().split(/\s+/).filter(Boolean);
    if (!words.length) return options;
    return options.filter((o) => words.every((w) => o.search.includes(w)));
}

export default TIMEZONES;
