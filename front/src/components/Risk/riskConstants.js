// Shared presentation constants for the Risk Intelligence screens.
// Palette values come from the Figma chart exports.

// "very_high" is absent from the Figma donut (the design predates the
// five-level split in service.py::_risk_level) so it borrows #345D9D, which the
// Zone chart already uses — see front/RISK_FRONTEND_BACKEND_REQUIREMENTS.md.
export const RISK_LEVEL_COLORS = {
    low: "#27E7B8",
    medium: "#4FC3C7",
    high: "#26AD85",
    very_high: "#345D9D",
    critical: "#5F36D3",
};

export const CATEGORY_COLORS = [
    "#27E7B8",
    "#4FC3C7",
    "#5F36D3",
    "#26AD85",
    "#35ECB5",
    "#345D9D",
];

export const TREND_BAR_COLOR = "#29354E";

/** "very_high" -> "Very High"; also covers labels the backend adds later. */
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
