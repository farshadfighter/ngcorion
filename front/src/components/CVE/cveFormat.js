import { t, uiLocale, n } from "../../i18n";
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

/** Rough package-version order for display (numbers compared as numbers, "~" first). */
export function versionCompare(a, b) {
    const tok = (v) => String(v || "").replace(/^\d+:/, "").match(/~|\d+|[a-z]+/gi) || [];
    const x = tok(a);
    const y = tok(b);
    for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
        const p = x[i];
        const q = y[i];
        if (p === q) continue;
        if (p === undefined) return q === "~" ? 1 : -1;
        if (q === undefined) return p === "~" ? -1 : 1;
        if (p === "~" || q === "~") return p === "~" ? -1 : 1;
        const pn = /^\d+$/.test(p);
        const qn = /^\d+$/.test(q);
        if (pn && qn) return Number(p) < Number(q) ? -1 : 1;
        if (pn !== qn) return pn ? 1 : -1;
        return p < q ? -1 : 1;
    }
    return 0;
}

export function epssColor(p) {
    if (p >= 0.5) return "#b91c1c";
    if (p >= 0.1) return "#c2410c";
    if (p >= 0.01) return "#ca8a04";
    return "#94a3b8";
}

export function epssLabel(p) {
    if (p == null) return "—";
    const pct = p * 100;
    return n(pct >= 10 ? `${Math.round(pct)}%` : pct >= 1 ? `${pct.toFixed(1)}%` : `${pct.toFixed(2)}%`);
}

export const KIND_LABEL = {
    online: t("Online update"),
    full: t("Full download"),
    offline: t("Package import"),
    bundle: t("Bundled database"),
    export: t("Package export"),
    advisories: t("Distribution advisories"),
    adv_import: t("Distribution advisories · file"),
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

// The advisory jobs share step names with the CVE jobs but not their meaning.
export const ADV_STEP_LABEL = {
    connect: t("Connect to OSV.dev"),
    download: t("Download the advisories"),
    apply: t("Check and apply"),
    verify: t("Read the file"),
};
export const isAdvisoryJob = (kind) => kind === "advisories" || kind === "adv_import";

/** "ubuntu:22.04" -> "Ubuntu 22.04 LTS" (the same labels as the server). */
export function releaseLabel(release) {
    const [distro, version = ""] = String(release || "").split(":");
    const names = { ubuntu: "Ubuntu", debian: "Debian", rhel: "Red Hat Enterprise Linux", rocky: "Rocky Linux", alma: "AlmaLinux" };
    const lts = distro === "ubuntu" && /^\d\d\.04$/.test(version) && Number(version.slice(0, 2)) % 2 === 0;
    return `${names[distro] || distro} ${version}${lts ? " LTS" : ""}`.trim();
}

export const ACTIVE = ["queued", "running"];
