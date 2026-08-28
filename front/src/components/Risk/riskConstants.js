// Shared presentation constants for the Risk Intelligence screens.
// Palette values come from the Figma chart exports.

// "informational" is absent from the Figma donut (the design predates the
// spec's five-band alignment in app/modules/risk/levels.py) so it borrows a
// neutral gray, distinct from the four original colours — see
// front/RISK_FRONTEND_BACKEND_REQUIREMENTS.md.
export const RISK_LEVEL_COLORS = {
    informational: "#9CA3AF",
    low: "#27E7B8",
    medium: "#4FC3C7",
    high: "#26AD85",
    critical: "#5F36D3",
};

/**
 * Badge palette for risk levels — a tinted background with a readable text
 * colour, matching the pill styling the Hardening and Auditing tables already
 * use so the three screens look like one product.
 *
 * RISK_LEVEL_COLORS above stays as-is: those are the saturated chart fills, too
 * strong to sit behind table text.
 */
export const RISK_LEVEL_BADGES = {
    informational: { bg: "#F1F5F9", fg: "#475569" },
    low: { bg: "#D1FAE5", fg: "#065F46" },
    medium: { bg: "#E0E7FF", fg: "#3730A3" },
    high: { bg: "#FEF3C7", fg: "#92400E" },
    critical: { bg: "#FEE2E2", fg: "#991B1B" },
};

/** Severity order, lowest first — risk_level is a string in the database, so
 *  sorting on it directly gives alphabetical nonsense (critical next to low). */
export const RISK_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"];

export const CATEGORY_COLORS = [
    "#27E7B8",
    "#4FC3C7",
    "#5F36D3",
    "#26AD85",
    "#35ECB5",
    "#345D9D",
];

export const TREND_BAR_COLOR = "#29354E";

/** "informational" -> "Informational"; also covers labels the backend adds later. */
export const titleCase = (value) =>
    String(value)
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");

export const formatNumber = (value) =>
    typeof value === "number" ? value.toLocaleString("en-US") : value;

/** Table cells render "-" for absent values, matching the Figma mock. */
export const orDash = (value) =>
    value === null || value === undefined || value === "" ? "-" : value;

export const formatDate = (value) => {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "-";
    return `${date.getFullYear()}/${date.getMonth() + 1}/${date.getDate()}`;
};
