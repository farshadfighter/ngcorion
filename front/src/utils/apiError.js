import { t } from "../i18n";
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

/**
 * Why there is no message when the server sent none of its own: the request ran out of time (the work
 * may still finish there), nothing answered, or a 5xx came back without a body the app wrote (an
 * unexpected error, or the proxy in front). Translated; null when the server did answer.
 */
export function noAnswerText(err) {
    if (err?.code === "ECONNABORTED" || err?.code === "ETIMEDOUT") {
        return t("The server did not answer in time. The work may still finish there: look again in a minute.");
    }
    const status = err?.response?.status;
    if (!status) return err?.request ? t("The server could not be reached. Check the connection and try again.") : null;
    if (status >= 500) return t("The server answered with error {{status}} and no message. The server log has the cause.", { status });
    return null;
}
