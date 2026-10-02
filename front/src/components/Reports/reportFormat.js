import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";

// Shared labels and helpers for the report pages.

export const STATUS = {
    queued: { label: t("Waiting to start"), pill: "rep-st-run" },
    running: { label: t("Being built"), pill: "rep-st-run" },
    ready: { label: t("Ready"), pill: "rep-st-ok" },
    failed: { label: t("Failed"), pill: "rep-st-fail" },
    cancelled: { label: t("Cancelled"), pill: "rep-st-grey" },
};

export const CLASSIFICATIONS = [
    ["public", t("Public")],
    ["internal", t("Internal")],
    ["confidential", t("Confidential")],
];

export const PERIODS = [
    ["last_7_days", t("Last 7 days")],
    ["last_30_days", t("Last 30 days")],
    ["previous_month", t("Previous month")],
    ["previous_quarter", t("Previous quarter")],
    ["year_to_date", t("This year so far")],
    ["custom", t("Custom dates")],
];

export const SCOPES = [
    ["all", t("All assets")],
    ["types", t("Asset type")],
    ["sites", t("Site")],
    ["owners", t("Owner")],
    ["zones", t("Zone")],
    ["assets", t("Pick assets")],
];

export const FREQUENCIES = [
    ["daily", t("Daily")],
    ["weekly", t("Weekly")],
    ["monthly", t("Monthly")],
    ["quarterly", t("Quarterly")],
];

// Python weekday numbers (0 = Monday), listed from Saturday as the Persian week starts.
export const WEEKDAYS = [
    [5, t("Saturday")], [6, t("Sunday")], [0, t("Monday")], [1, t("Tuesday")],
    [2, t("Wednesday")], [3, t("Thursday")], [4, t("Friday")],
];

export const label = (pairs, value) => (pairs.find(([v]) => v === value) || [null, value])[1];

export const fileSize = (bytes) => {
    if (bytes == null) return "";
    if (bytes < 1024) return t("{{size}} B", { size: n(bytes) });
    if (bytes < 1024 * 1024) return t("{{size}} KB", { size: n(Math.round(bytes / 1024)) });
    return t("{{size}} MB", { size: n((bytes / 1024 / 1024).toFixed(1)) });
};

export const errorText = (e, fallback) => {
    const d = e?.response?.data?.detail;
    return typeof d === "string" ? tb(d) : fallback;
};

/** Save a report file through the API (the token travels with the request). */
export async function download(report, kind) {
    const res = await api.get(`/api/reports/${report.id}/files/${kind}`, { responseType: "blob" });
    const file = (report.files || []).find((f) => f.kind === kind);
    const url = URL.createObjectURL(res.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = file?.filename || `${report.code}.${kind}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** How a period preset reads in a list: "Previous month", or the custom dates. */
export function periodText(params) {
    const p = params?.period || {};
    if (p.preset === "custom" && p.from && p.to) return `${p.from} – ${p.to}`;
    return label(PERIODS, p.preset) || "—";
}
