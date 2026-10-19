import { tb } from "../i18n/backendText";

/**
 * An API error as text a page can show. FastAPI answers a refused body (422) with `detail` as a list of
 * {loc, msg} objects, which React cannot render: storing that list as the error turned a page white.
 * Each message names its field ("ports: Input should be a valid integer").
 */
export function apiErrorText(err, fallback) {
    const detail = err?.response?.data?.detail;
    if (typeof detail === "string" && detail) return tb(detail);
    if (Array.isArray(detail) && detail.length) {
        return detail.map((d) => {
            const field = Array.isArray(d?.loc) ? d.loc.filter((x) => x !== "body").join(".") : "";
            const msg = tb(String(d?.msg || "").replace(/^Value error, /, ""));
            return field ? `${field}: ${msg}` : msg;
        }).join(" · ");
    }
    return fallback;
}
