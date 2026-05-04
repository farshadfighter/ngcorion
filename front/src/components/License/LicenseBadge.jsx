import { useSelector } from "react-redux";
import { LICENSE_TYPES } from "./licenseConfig";

const MODULE_CONFIG = {
    auditing: { label: "Auditing", icon: "📋", usedKey: "used_audits", maxKey: "max_audits" },
    autoDiscovery: { label: "Discovery", icon: "🔍", usedKey: "used_discoveries", maxKey: "max_discoveries" },
    assetList: { label: "Asset", icon: "📦", usedKey: "used_assets", maxKey: "max_assets" },
    hardening: { label: "Hardening", icon: "🛡️", usedKey: "used_hardens", maxKey: "max_hardens" },
};

export const LicenseBadge = ({ module }) => {
    const { isValid, planType, usage, limits } = useSelector((state) => state.license);

    if (!isValid || !planType) return null;

    const license = LICENSE_TYPES[planType];
    if (!license) return null;

    const config = MODULE_CONFIG[module];
    if (!config) return null;

    const usedValue = usage?.[config.usedKey] ?? 0;
    const maxValue = limits?.[config.maxKey] ?? null;
    const displayMax = maxValue === null ? "∞" : maxValue;
    const isLimitReached = maxValue !== null && usedValue >= maxValue;

    return (
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {/* نام لایسنس */}
            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                backgroundColor: "#ffffff",
                border: `1px solid ${license.borderColor}`,
                borderRadius: "8px",
                padding: "6px 14px",
                fontSize: "13px",
                fontWeight: "500",
                color: "#374151",
            }}>
                <span><img src="/icons/haedenIcon.svg" alt="" className="section-icon" /></span>
                <span>{license.name}</span>
            </div>

            {/* استفاده ماژول */}
            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                backgroundColor: isLimitReached ? "#FEF2F2" : "#1e3a5f",
                border: `1px solid ${isLimitReached ? "#FECACA" : "#1e3a5f"}`,
                borderRadius: "8px",
                padding: "6px 14px",
                fontSize: "13px",
                fontWeight: "600",
                color: isLimitReached ? "#DC2626" : "#ffffff",
            }}>
                <span>{config.icon}</span>
                <span>{config.label}</span>
                <span>{usedValue}/{displayMax}</span>
            </div>
        </div>
    );
};