/**
 * One plan of the catalog (or the add-on pack) on the License page.
 */
import { ADDON, planLabel } from "./licenseConfig";
import { t, n } from "../../i18n";
import { tx } from "../../i18n/tx";

export const LicenseCard = ({ plan, isActive = false, addon = false }) => {
    const color = addon ? "#64748B" : plan.color;
    const title = addon ? t("Add-on pack") : planLabel(plan.code);
    const code = addon ? ADDON.code : plan.code;
    const assets = addon ? `+${n(ADDON.assets)}` : plan.assets === null ? t("Unlimited") : n(plan.assets);
    return (
        <div style={{
            border: isActive ? `2px solid ${color}` : "1px solid #e5e7eb",
            borderTop: `4px solid ${color}`,
            borderRadius: "12px",
            padding: "18px 18px 16px",
            backgroundColor: isActive ? "#F8FAFC" : "#ffffff",
            display: "flex", flexDirection: "column", gap: "10px", minWidth: 0,
        }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "8px" }}>
                <div style={{ fontWeight: 700, fontSize: "15px", color: "#111827", lineHeight: 1.4 }}>{title}</div>
                {isActive && (
                    <span style={{
                        fontSize: "11px", fontWeight: 700, color: "white", backgroundColor: color,
                        borderRadius: "20px", padding: "3px 10px", whiteSpace: "nowrap",
                    }}>
                        {t("Current")}
                    </span>
                )}
            </div>
            <div style={{ fontSize: "11px", color: "#6B7280", fontFamily: "monospace" }} dir="ltr">{code}</div>
            <div style={{ display: "flex", alignItems: "baseline", gap: "6px" }}>
                <span style={{ fontSize: "26px", fontWeight: 800, color, fontVariantNumeric: "tabular-nums" }}>{assets}</span>
                <span style={{ fontSize: "13px", color: "#6B7280" }}>{t("assets")}</span>
            </div>
            <div style={{ fontSize: "12.5px", color: "#4B5563", lineHeight: 1.7 }}>
                {addon ? (
                    t("Extends any plan except the pilot and Unlimited; the term follows the license.")
                ) : (
                    <>
                        <div>{tx("Term: {{duration}}", { duration: plan.duration })}</div>
                        <div>{plan.addons ? t("Add-on packs available") : plan.pilot ? t("Trial; no add-ons") : t("No limit; no add-ons needed")}</div>
                    </>
                )}
            </div>
        </div>
    );
};
