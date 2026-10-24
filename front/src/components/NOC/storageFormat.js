/** Share of a storage budget in use (0-100, one decimal) and its tone; null without a budget. */
export const usagePct = (used, budget) => (budget > 0 ? Math.min(100, Math.round((used / budget) * 1000) / 10) : null);

export const usageTone = (pct) => (pct === null ? "" : pct >= 90 ? "is-high" : pct >= 70 ? "is-warn" : "is-ok");
