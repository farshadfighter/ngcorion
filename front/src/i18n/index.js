/**
 * Translations (English and Persian).
 *
 * Keys are the English text itself ("Save rule", "{{count}} devices"), so a
 * string without a Persian entry simply shows in English. The Persian texts
 * live in ./locales/fa/*.json, one file per area of the app; `npm run
 * i18n:check` lists anything not yet translated.
 *
 * `t` is a plain function, usable anywhere (components, slices, module-level
 * constants). Changing the language reloads the page, so nothing has to
 * re-render live - the language is chosen before any module renders.
 */
import i18next from "i18next";

const faModules = import.meta.glob("./locales/fa/*.json", { eager: true });
const enModules = import.meta.glob("./locales/en/*.json", { eager: true });

function merge(modules) {
    return Object.values(modules).reduce((all, m) => Object.assign(all, m.default || m), {});
}

export const LANGUAGES = [
    { code: "en", label: "English", dir: "ltr" },
    { code: "fa", label: "فارسی", dir: "rtl" },
];
const SUPPORTED = LANGUAGES.map((l) => l.code);
const STORAGE_KEY = "lang";

function initialLanguage() {
    try {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (SUPPORTED.includes(saved)) return saved;
    } catch { /* storage blocked */ }
    const browser = (typeof navigator !== "undefined" && navigator.language || "").slice(0, 2);
    return SUPPORTED.includes(browser) ? browser : "en";
}

const language = initialLanguage();

// Numbers inside translated sentences follow the language's digits (۱۲۳ in Persian).
const numberFormat = new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US");

i18next.init({
    lng: language,
    fallbackLng: "en",
    resources: { en: { translation: merge(enModules) }, fa: { translation: merge(faModules) } },
    keySeparator: false,
    nsSeparator: false,
    returnEmptyString: false,
    interpolation: { escapeValue: false },
    initAsync: false,
});

/**
 * Translate an English text. In Persian, numbers passed in `options` are
 * written in Persian digits; `count` (which also picks the plural form) is
 * formatted by the text itself with {{count, number}}.
 */
export function t(key, options) {
    if (options && language === "fa") {
        const out = {};
        for (const [k, v] of Object.entries(options)) {
            out[k] = typeof v === "number" && k !== "count" ? numberFormat.format(v) : v;
        }
        return i18next.t(key, out);
    }
    return i18next.t(key, options);
}

/** Marks a string for translation where it is defined; translate it with t() where it is shown. */
export const _t = (key) => key;

export const currentLanguage = () => language;

/** True when this browser has an explicit choice (sign-in page or user menu). */
export function hasStoredLanguage() {
    try { return SUPPORTED.includes(localStorage.getItem(STORAGE_KEY)); } catch { return false; }
}
export const isRtl = () => language === "fa";

/** A number in the current language's digits. */
export function n(value) {
    if (value === null || value === undefined || value === "") return value;
    if (typeof value === "number") return numberFormat.format(value);
    // Already-formatted figures such as "54%" or "34/100".
    if (language === "fa" && typeof value === "string" && /^[\d\s.,%/+\-−]+$/.test(value)) {
        const out = value.replace(/(\d)\.(\d)/g, "$1٫$2").replace(/\d/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[d]).replace(/%/g, "٪");
        // After Persian letters the bidi algorithm reverses "10-24" or "34/100"; keep them left-to-right.
        return /[-/−]/.test(out) ? `\u2066${out}\u2069` : out;
    }
    return value;
}

/**
 * Locale for toLocale*String / Intl: Persian with the Solar Hijri calendar and
 * Persian digits, or US English. Works for numbers and dates alike.
 */
export const uiLocale = () => (language === "fa" ? "fa-IR-u-ca-persian" : "en-US");

export function applyDocumentLanguage() {
    const html = document.documentElement;
    html.lang = language;
    html.dir = language === "fa" ? "rtl" : "ltr";
}

/** Switch language: remembered on this browser, and the page reloads in it. */
export function setLanguage(code, { reload = true } = {}) {
    if (!SUPPORTED.includes(code)) return;
    try { localStorage.setItem(STORAGE_KEY, code); } catch { /* storage blocked */ }
    if (reload && code !== language) window.location.reload();
}

export default i18next;
