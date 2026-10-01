import { t, uiLocale } from "../../i18n";
// Shared formatting for the CVE pages.

export { parseUtc, formatWhen, formatDate, ageDays } from "../../utils/dates.js";

export const num = (n) => (n == null ? "—" : Number(n).toLocaleString(uiLocale()));

export function formatBytes(n) {
    if (!n) return t("{{value}} MB", { value: 0 });
    if (n < 1024 * 1024) return t("{{value}} KB", { value: Math.max(1, Math.round(n / 1024)) });
    if (n < 1024 * 1024 * 1024) return t("{{value}} MB", { value: Number((n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)) });
    return t("{{value}} GB", { value: Number((n / (1024 * 1024 * 1024)).toFixed(1)) });
}

export const SEVERITY = {
    critical: { label: t("Critical"), fg: "#991b1b", bg: "#fee2e2" },
    high: { label: t("High"), fg: "#9a3412", bg: "#ffedd5" },
    medium: { label: t("Medium"), fg: "#854d0e", bg: "#fef9c3" },
    low: { label: t("Low"), fg: "#374151", bg: "#f3f4f6" },
    none: { label: t("None"), fg: "#374151", bg: "#f3f4f6" },
};

export const PRIORITY = {
    1: { label: t("Fix now"), fg: "#ffffff", bg: "#b91c1c", hint: t("Exploited in the wild (CISA KEV)") },
    2: { label: t("Next"), fg: "#9a3412", bg: "#ffedd5", hint: t("CVSS 9+ or a high chance of exploitation") },
    3: { label: t("Planned"), fg: "#854d0e", bg: "#fef9c3", hint: t("CVSS 7+ or a real chance of exploitation") },
    4: { label: t("Monitor"), fg: "#374151", bg: "#f3f4f6", hint: t("Lower risk") },
};

export function epssColor(p) {
    if (p >= 0.5) return "#b91c1c";
    if (p >= 0.1) return "#c2410c";
    if (p >= 0.01) return "#ca8a04";
    return "#94a3b8";
}

export function epssLabel(p) {
    if (p == null) return "—";
    const pct = p * 100;
    return pct >= 10 ? `${Math.round(pct)}%` : pct >= 1 ? `${pct.toFixed(1)}%` : `${pct.toFixed(2)}%`;
}

export const KIND_LABEL = {
    online: t("Online update"),
    full: t("Full download"),
    offline: t("Package import"),
    bundle: t("Bundled database"),
    export: t("Package export"),
};

export const STEP_LABEL = {
    connect: t("Connect to NVD"),
    download: t("Download CVEs"),
    kev: t("Known exploited list (CISA KEV)"),
    epss: t("Exploit likelihood (FIRST EPSS)"),
    apply: t("Check and apply"),
    verify: t("Check the package"),
    export: t("Write the package"),
};

export const ACTIVE = ["queued", "running"];
