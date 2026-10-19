import { tb } from "../i18n/backendText";

/**
 * API errors as something a page can show. FastAPI answers a refused body (422) with `detail` as a list
 * of {type, loc, msg, input} objects, and some endpoints with an object ({error_type, message});
 * storing either as a page's error and rendering it threw and turned the page white.
 */

/** A 422 list as one line naming each field ("ports: Input should be a valid integer · ..."). */
const listText = (detail) => detail.map((d) => {
    const field = Array.isArray(d?.loc) ? d.loc.filter((x) => x !== "body").join(".") : "";
    const msg = tb(String(d?.msg ?? d ?? "").replace(/^Value error, /, ""));
    return field ? `${field}: ${msg}` : msg;
}).join(" · ");

/**
 * The error a Redux slice keeps: the server's own text unchanged (pages translate or compare it), a list
 * or an object made into text, or `fallback` when the server said nothing.
 */
export function apiErrorDetail(err, fallback) {
    const detail = err?.response?.data?.detail;
    if (typeof detail === "string" && detail) return detail;
    if (Array.isArray(detail) && detail.length) return listText(detail);
    if (detail && typeof detail === "object") {
        const text = detail.message || detail.error || detail.detail;
        if (typeof text === "string" && text) return text;
    }
    return fallback;
}

/** The same, translated for showing directly. */
export function apiErrorText(err, fallback) {
    const text = apiErrorDetail(err, fallback);
    return typeof text === "string" && text !== fallback ? tb(text) : text;
}
