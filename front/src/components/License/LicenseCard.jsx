import { LICENSE_TYPES, MODULE_LABELS, MODULE_ICONS, API_FIELD_MAP } from "./licenseConfig";
import { getModuleLimit, formatExpiryDate, isLicenseExpired } from "./licenseHelpers";

export const LicenseCard = ({ licenseType, isActive = false, apiData = null, onActivate }) => {
    const license = LICENSE_TYPES[licenseType];
    if (!license) return null;

    const expired = apiData ? isLicenseExpired(apiData.expires_at) : false;

    return (
        <div
            style={{
                border: `1px solid #e5e7eb`,
                borderBottom: `3px solid ${license.borderColor}`,
                borderRadius: "12px",
                padding: "20px 24px",
                backgroundColor: "#ffffff",
                marginBottom: "16px",
                opacity: expired ? 0.6 : 1,
            }}
        >
            {/* Header کارت */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div
                        style={{
                            width: "42px",
                            height: "42px",
                            borderRadius: "8px",
                            backgroundColor: license.bgColor,
                            border: `1px solid ${license.borderColor}`,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "20px",
                        }}
                    >
                        🪪
                    </div>

                    <div>
                        <div style={{ fontSize: "18px", fontWeight: "600", color: "#111827" }}>
                            {license.name}
                        </div>
                        {apiData?.expires_at && (
                            <div style={{ fontSize: "12px", color: expired ? "#EF4444" : "#6B7280", marginTop: "2px" }}>
                                {expired ? "⛔ Expired" : `✅ Expires: ${formatExpiryDate(apiData.expires_at)}`}
                            </div>
                        )}
                    </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <div
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            backgroundColor: "#F3F4F6",
                            borderRadius: "20px",
                            padding: "6px 14px",
                            fontSize: "13px",
                            color: "#6B7280",
                        }}
                    >
                        <span>🕐</span>
                        <span>licence time: {license.duration}</span>
                    </div>

                    {isActive && (
                        <div
                            style={{
                                backgroundColor: license.bgColor,
                                border: `1px solid ${license.borderColor}`,
                                color: license.borderColor,
                                borderRadius: "20px",
                                padding: "6px 14px",
                                fontSize: "12px",
                                fontWeight: "600",
                            }}
                        >
                            ✓ Active
                        </div>
                    )}
                </div>
            </div>

            {/* ماژول‌ها */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
                {Object.keys(MODULE_LABELS).map((module) => {
                    const { used: usedKey } = API_FIELD_MAP[module];
                    const usedValue = apiData ? apiData[usedKey] ?? 0 : null;
                    const limit = getModuleLimit(licenseType, module);

                    return (
                        <div
                            key={module}
                            style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "6px",
                                border: "1px solid #E5E7EB",
                                borderRadius: "8px",
                                padding: "8px 14px",
                                backgroundColor: "#F9FAFB",
                                fontSize: "13px",
                                color: "#374151",
                            }}
                        >
                            <span>{MODULE_ICONS[module]}</span>
                            <span>{MODULE_LABELS[module]}</span>
                            <span style={{ fontWeight: "700", color: license.borderColor, marginLeft: "4px" }}>
                                {usedValue !== null ? `${usedValue}/` : ""}{limit}
                            </span>
                        </div>
                    );
                })}
            </div>

            {/* دکمه activate */}
            {!isActive && onActivate && (
                <div style={{ marginTop: "16px", display: "flex", justifyContent: "flex-end" }}>
                    <button
                        onClick={() => onActivate(licenseType)}
                        style={{
                            padding: "8px 20px",
                            borderRadius: "8px",
                            border: "none",
                            backgroundColor: license.borderColor,
                            color: "#ffffff",
                            fontSize: "13px",
                            fontWeight: "600",
                            cursor: "pointer",
                        }}
                    >
                        Activate
                    </button>
                </div>
            )}
        </div>
    );
};