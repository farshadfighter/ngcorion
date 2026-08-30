// Shared presentation constants for the Risk Intelligence screens.
// Palette values come from the Figma chart exports.

/**
 * Saturated fills for the donut charts — the same green-to-red ramp as
 * RISK_LEVEL_BADGES below, just at chart strength.
 *
 * The Figma palette these came from carried no severity meaning: high was a
 * dark green (#26AD85) and critical a purple (#5F36D3), so the worst two bands
 * read as "fine" and "unrelated" while low was also green. Severity has to be
 * legible from colour alone in a chart, where there is no text to fall back on.
 */
export const RISK_LEVEL_COLORS = {
    informational: "#94A3B8",
    low: "#22C55E",
    medium: "#EAB308",
    high: "#F97316",
    critical: "#DC2626",
};

/**
 * Badge palette for risk levels — the tinted, text-safe version of
 * RISK_LEVEL_COLORS above, used by the pills in the Risk, Hardening and
 * Auditing tables so the three screens look like one product.
 *
 * Same green -> yellow -> orange -> red ramp, so a level keeps its colour
 * whether it appears as a chart slice or a table pill. medium used to be blue,
 * which sat outside the ramp and made high (yellow) look like the middle of it.
 */
export const RISK_LEVEL_BADGES = {
    informational: { bg: "#F1F5F9", fg: "#475569" },
    low: { bg: "#DCFCE7", fg: "#166534" },
    medium: { bg: "#FEF9C3", fg: "#854D0E" },
    high: { bg: "#FFEDD5", fg: "#9A3412" },
    critical: { bg: "#FEE2E2", fg: "#991B1B" },
};

/** Severity order, lowest first — risk_level is a string in the database, so
 *  sorting on it directly gives alphabetical nonsense (critical next to low). */
export const RISK_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"];

/**
 * Slice colours for the charts whose categories carry no severity (zone,
 * confidentiality). Picked to stay distinguishable side by side: the previous
 * set held four near-identical teals/greens (#27E7B8, #26AD85, #35ECB5,
 * #4FC3C7), so neighbouring slices blurred into one another.
 *
 * Deliberately avoids the red/orange/green of RISK_LEVEL_COLORS, so a zone
 * slice is never mistaken for a severity.
 */
export const CATEGORY_COLORS = [
    "#3B82F6",
    "#8B5CF6",
    "#06B6D4",
    "#EC4899",
    "#6366F1",
    "#14B8A6",
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
