import { MODULE_LABELS, MODULE_ICONS, API_FIELD_MAP } from "./licenseConfig";
import { getLicenseInfo, formatExpiryDate, isLicenseExpired } from "./licenseHelpers";

export const LicenseHeader = ({ licenseType, apiData = null }) => {
    const license = getLicenseInfo(licenseType);
    if (!license) return null;

    const expired = apiData ? isLicenseExpired(apiData.expires_at) : false;

    return (
        <div
            style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                backgroundColor: "#ffffff",
                border: "1px solid #E5E7EB",
                borderLeft: `4px solid ${license.borderColor}`,
                borderRadius: "10px",
                padding: "10px 20px",
                marginBottom: "24px",
                flexWrap: "wrap",
                gap: "12px",
            }}
        >
            {/* سمت چپ: نام لایسنس */}
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <div
                    style={{
                        width: "34px",
                        height: "34px",
                        borderRadius: "6px",
                        backgroundColor: license.bgColor,
                        border: `1px solid ${license.borderColor}`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: "16px",
                    }}
                >
                    ⛔
                </div>
                <div>
                    <div style={{ fontSize: "11px", color: "#9CA3AF" }}>Active Licence</div>
                    <div style={{ fontSize: "14px", fontWeight: "600", color: "#111827" }}>
                        {license.name}
                    </div>
                    {apiData?.expires_at && (
                        <div style={{ fontSize: "11px", color: expired ? "#EF4444" : "#6B7280" }}>
                            {expired ? "⛔ Expired" : `Expires: ${formatExpiryDate(apiData.expires_at)}`}
                        </div>
                    )}
                </div>
            </div>

            {/* سمت راست: استفاده هر ماژول */}
            <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
                {Object.keys(MODULE_LABELS).map((module) => {
                    const { used: usedKey, max: maxKey } = API_FIELD_MAP[module];
                    const usedValue = apiData ? apiData[usedKey] ?? 0 : 0;
                    const maxValue = apiData ? apiData[maxKey] : null;
                    const displayMax = maxValue === null ? "∞" : maxValue;

                    return (
                        <div
                            key={module}
                            style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "5px",
                                fontSize: "12px",
                                color: "#6B7280",
                            }}
                        >
                            <span>{MODULE_ICONS[module]}</span>
                            <span>{MODULE_LABELS[module]}:</span>
                            <span style={{ fontWeight: "600", color: "#111827" }}>
                                {usedValue}/{displayMax}
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};