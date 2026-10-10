/**
 * Header badge on the license-relevant pages: the plan, and the assets in the
 * inventory against the license's limit.
 */
import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { getLicenseUsageThunk } from "../../store/licenseSlice";
import { planLabel } from "./licenseConfig";
import { n, t } from "../../i18n";

const LicenseBadge = () => {
    const dispatch = useDispatch();
    const { isValid, planCode, planName, maxAssets, usage, offlinePilot } = useSelector((state) => state.license);

    useEffect(() => {
        if (isValid) dispatch(getLicenseUsageThunk());
    }, [isValid, dispatch]);

    const unlimited = maxAssets === null || maxAssets === undefined;
    const used = usage?.used;
    const over = !!usage?.over_limit;
    const accent = over ? "#FCA5A5" : offlinePilot ? "#FCD34D" : "#7aaddb";

    return (
        <div style={{
            display: "flex", alignItems: "stretch", borderRadius: "10px", overflow: "hidden",
            border: "1px solid #d1d9e6", boxShadow: "0 1px 4px rgba(0,0,0,0.07)", height: "44px",
        }} title={over ? t("More assets than the license covers") : undefined}>
            <div style={{
                display: "flex", alignItems: "center", gap: "8px", padding: "0 14px",
                backgroundColor: "#ffffff", borderInlineEnd: "1px solid #d1d9e6",
            }}>
                <i className="fa-solid fa-id-card" style={{ fontSize: "15px", color: "#1d2939" }} />
                <span style={{ fontSize: "13px", fontWeight: 700, color: "#1d2939", whiteSpace: "nowrap" }}>
                    {offlinePilot ? t("Pilot (offline)") : isValid ? planLabel(planCode, planName) : t("No Active Licence")}
                </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "0 14px", backgroundColor: "#0f2044" }}>
                <i className={`fa-solid ${over ? "fa-triangle-exclamation" : "fa-server"}`} style={{ fontSize: "14px", color: accent }} />
                <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.35 }}>
                    <span style={{ fontSize: "12px", fontWeight: 500, color: "#e6f1fb", whiteSpace: "nowrap" }}>{t("Assets")}</span>
                    <span style={{ fontSize: "11px", color: accent, fontVariantNumeric: "tabular-nums" }}>
                        {used === undefined || used === null ? "—" : n(used)}/{unlimited ? "∞" : n(maxAssets)}
                    </span>
                </div>
            </div>
        </div>
    );
};

export default LicenseBadge;
