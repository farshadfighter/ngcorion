// Display-only mirror of the backend plan catalog.
//
// SOURCE OF TRUTH is the license server: license_server/app/crud.py
// (get_plan_limits) and license_server/app/models.py (PlanType enum). This file
// is a hand-copied mirror so the Generate form can preview limits/duration
// without a round trip. It is NOT shared code — if the backend plans change,
// update this list to match. Limits of `null` mean unlimited.

export const PLANS = [
  {
    value: "pilot",
    label: "Pilot",
    blurb: "30-day trial",
    durationDays: 30,
    limits: { assets: 5, discoveries: 2, audits: 2, hardens: 2, monitors: 2 },
  },
  {
    value: "basic1",
    label: "Basic 1 — Small network",
    blurb: "Up to 15 devices",
    durationDays: 365,
    limits: { assets: 15, discoveries: 15, audits: 15, hardens: 15, monitors: 15 },
  },
  {
    value: "basic2",
    label: "Basic 2 — Medium network",
    blurb: "Up to 50 devices",
    durationDays: 365,
    limits: { assets: 50, discoveries: 50, audits: 50, hardens: 50, monitors: 50 },
  },
  {
    value: "basic3",
    label: "Basic 3 — Large network",
    blurb: "Up to 150 devices",
    durationDays: 365,
    limits: { assets: 150, discoveries: 150, audits: 150, hardens: 150, monitors: 150 },
  },
  {
    value: "enterprise",
    label: "Enterprise",
    blurb: "Unlimited",
    durationDays: 365,
    limits: { assets: null, discoveries: null, audits: null, hardens: null, monitors: null },
  },
];

export const PLAN_BY_VALUE = Object.fromEntries(PLANS.map((p) => [p.value, p]));

export function planLabel(value) {
  return PLAN_BY_VALUE[value]?.label || value;
}

// The five quota dimensions, in display order. Field names match the API
// LicenseResponse (max_<x> / used_<x>).
export const OPERATIONS = ["assets", "discoveries", "audits", "hardens", "monitors"];
