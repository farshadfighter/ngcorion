// Shared formatting for the CVE pages.

// The API sends naive UTC timestamps ("2026-10-01T02:00:00").
export function parseUtc(value) {
    if (!value) return null;
    const s = String(value);
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) || s.length <= 10 ? s : `${s}Z`);
    return Number.isNaN(d.getTime()) ? null : d;
}

const pad = (n) => String(n).padStart(2, "0");

export function formatWhen(value) {
    const d = parseUtc(value);
    if (!d) return "—";
    const now = new Date();
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const diff = Math.round((today - day) / 86400000);
    if (diff === 0) return `Today ${time}`;
    if (diff === 1) return `Yesterday ${time}`;
    return `${d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })} ${time}`;
}

export function formatDate(value) {
    const d = parseUtc(value);
    return d ? d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—";
}

export function ageDays(value) {
    const d = parseUtc(value);
    return d ? (Date.now() - d.getTime()) / 86400000 : null;
}

export const num = (n) => (n == null ? "—" : Number(n).toLocaleString());

export function formatBytes(n) {
    if (!n) return "0 MB";
    if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export const SEVERITY = {
    critical: { label: "Critical", fg: "#991b1b", bg: "#fee2e2" },
    high: { label: "High", fg: "#9a3412", bg: "#ffedd5" },
    medium: { label: "Medium", fg: "#854d0e", bg: "#fef9c3" },
    low: { label: "Low", fg: "#374151", bg: "#f3f4f6" },
    none: { label: "None", fg: "#374151", bg: "#f3f4f6" },
};

export const PRIORITY = {
    1: { label: "Fix now", fg: "#ffffff", bg: "#b91c1c", hint: "Exploited in the wild (CISA KEV)" },
    2: { label: "Next", fg: "#9a3412", bg: "#ffedd5", hint: "CVSS 9+ or a high chance of exploitation" },
    3: { label: "Planned", fg: "#854d0e", bg: "#fef9c3", hint: "CVSS 7+ or a real chance of exploitation" },
    4: { label: "Monitor", fg: "#374151", bg: "#f3f4f6", hint: "Lower risk" },
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
    online: "Online update",
    full: "Full download",
    offline: "Package import",
    bundle: "Bundled database",
    export: "Package export",
};

export const STEP_LABEL = {
    connect: "Connect to NVD",
    download: "Download CVEs",
    kev: "Known exploited list (CISA KEV)",
    epss: "Exploit likelihood (FIRST EPSS)",
    apply: "Check and apply",
    verify: "Check the package",
    export: "Write the package",
};

export const ACTIVE = ["queued", "running"];
