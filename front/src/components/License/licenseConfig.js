/**
 * The NGCorion plans, for the License page.
 *
 * A license is sold per number of managed assets: the plan's assets plus
 * add-on packs of 50. Audits and hardening runs are not counted.
 *
 * Display-only mirror of the license server's catalog
 * (license_server/app/plans.py); what this installation may do comes from the
 * license itself (GET /api/license/status), never from this list.
 */
import { n, t } from "../../i18n";

export const ADDON = { code: "NGC-ADD-50-1Y", assets: 50 };

// Without contact with the license server: the license's plan for 48 hours,
// then the pilot (5 assets) for 30 days, then locked. Enforced by the backend
// (app/core/license_state.py); shown here for the explanation.
export const OFFLINE_GRACE_HOURS = 48;
export const PILOT = { code: "NGC-PILOT-5-1M", assets: 5, days: 30 };

export const PLANS = [
    { code: "NGC-PILOT-5-1M", name: "NGCorion Pilot", assets: 5, duration: t("1 month"), color: "#6B7280", pilot: true },
    { code: "NGC-ESS-25-1Y", name: "NGCorion Essential", assets: 25, duration: t("1 year"), color: "#0EA5E9" },
    { code: "NGC-PRO-100-1Y", name: "NGCorion Professional", assets: 100, duration: t("1 year"), color: "#3B82F6" },
    { code: "NGC-BUS-250-1Y", name: "NGCorion Business", assets: 250, duration: t("1 year"), color: "#10B981" },
    { code: "NGC-ENT-500-1Y", name: "NGCorion Enterprise", assets: 500, duration: t("1 year"), color: "#F59E0B" },
    { code: "NGC-ENT-1000-1Y", name: "NGCorion Enterprise", assets: 1000, duration: t("1 year"), color: "#F97316" },
    { code: "NGC-ENT-2500-1Y", name: "NGCorion Enterprise", assets: 2500, duration: t("1 year"), color: "#EF4444" },
    { code: "NGC-ENT-ULT-1Y", name: "NGCorion Enterprise Unlimited", assets: null, duration: t("1 year"), color: "#8B5CF6" },
].map((p) => ({ ...p, addons: p.assets !== null && !p.pilot }));

export const PLAN_BY_CODE = Object.fromEntries(PLANS.map((p) => [p.code, p]));

/** The plan's product name, with its size where the name alone is ambiguous ("NGCorion Enterprise 500"). */
export function planLabel(code, fallbackName) {
    const plan = PLAN_BY_CODE[code];
    if (!plan) return fallbackName || code || "";
    return plan.assets === null || plan.pilot ? plan.name : `${plan.name} ${n(plan.assets)}`;
}
