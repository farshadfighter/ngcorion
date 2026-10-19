import { t } from "../../../i18n";

/**
 * Labels and tones of a finding's hardening and verification status, as GET /api/risk/assets/{id}/findings
 * sends them (app/modules/risk/router.py, get_asset_findings).
 */
export const HARDENING = {
    not_hardened: { label: t("Not hardened"), tone: "neutral" },
    previewed: { label: t("Previewed only"), tone: "neutral" },
    running: { label: t("Running"), tone: "info" },
    applied: { label: t("Applied"), tone: "good" },
    failed: { label: t("Failed"), tone: "bad" },
};

export const VERIFICATION = {
    verified: { label: t("Verified"), tone: "good" },
    awaiting_reaudit: { label: t("Holds, awaiting re-audit"), tone: "warn",
                        hint: t("The fix was checked and holds; the finding reads failed until the next audit.") },
    not_verified: { label: t("Not verified"), tone: "warn",
                    hint: t("Nothing checked the device after the change: audit it again.") },
    still_failing: { label: t("Check still fails"), tone: "bad" },
};

export const AUDIT_NOW = {
    fail: { label: t("Failing"), tone: "bad" },
    pass: { label: t("Passing"), tone: "good" },
};

/** {label, tone, hint} for a status of one of the maps above; null when there is none. */
export const statusOf = (map, key) => (key ? map[key] || { label: key, tone: "neutral" } : null);
