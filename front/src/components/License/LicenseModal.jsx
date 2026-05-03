import { LICENSE_TYPES, MODULE_LABELS, MODULE_ICONS } from "./licenseConfig";
import { getModuleLimit } from "./licenseHelpers";

export const LicenseModal = ({ licenseType, onClose, onActivate }) => {
    const license = LICENSE_TYPES[licenseType];
    if (!license) return null;

    return (
        <>
            {/* Backdrop */}
            <div
                onClick={onClose}
                style={{
                    position: "fixed",
                    inset: 0,
                    backgroundColor: "rgba(0,0,0,0.4)",
                    zIndex: 1000,
                }}
            />

            {/* Modal */}
            <div
                style={{
                    position: "fixed",
                    top: "50%",
                    left: "50%",
                    transform: "translate(-50%, -50%)",
                    backgroundColor: "#ffffff",
                    borderRadius: "16px",
                    padding: "32px",
                    zIndex: 1001,
                    width: "480px",
                    maxWidth: "90vw",
                    boxShadow: "0 20px 60px rgba(0,0,0,0.15)",
                    borderTop: `4px solid ${license.borderColor}`,
                }}
            >
                {/* Header مودال */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "24px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                        <div
                            style={{
                                width: "46px",
                                height: "46px",
                                borderRadius: "10px",
                                backgroundColor: license.bgColor,
                                border: `1px solid ${license.borderColor}`,
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontSize: "22px",
                            }}
                        >
                            <img src="/icons/license.svg" alt="" className="section-icon" />
                        </div>
                        <div>
                            <div style={{ fontSize: "18px", fontWeight: "700", color: "#111827" }}>
                                {license.name}
                            </div>
                            <div style={{ fontSize: "13px", color: "#6B7280", marginTop: "2px" }}>
                                🕐 licence time: {license.duration}
                            </div>
                        </div>
                    </div>

                    {/* دکمه بستن */}
                    <button
                        onClick={onClose}
                        style={{
                            background: "none",
                            border: "none",
                            fontSize: "20px",
                            cursor: "pointer",
                            color: "#9CA3AF",
                            padding: "4px",
                            lineHeight: 1,
                        }}
                    >
                        ✕
                    </button>
                </div>

                {/* خط جدا کننده */}
                <div style={{ height: "1px", backgroundColor: "#F3F4F6", marginBottom: "24px" }} />

                {/* ماژول‌ها */}
                <div style={{ marginBottom: "28px" }}>
                    <div style={{ fontSize: "13px", color: "#6B7280", marginBottom: "12px", fontWeight: "500" }}>
                        Module Limits
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                        {Object.keys(MODULE_LABELS).map((module) => (
                            <div
                                key={module}
                                style={{
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "space-between",
                                    backgroundColor: "#F9FAFB",
                                    border: "1px solid #E5E7EB",
                                    borderRadius: "8px",
                                    padding: "10px 16px",
                                }}
                            >
                                <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "14px", color: "#374151" }}>
                                    <span>{MODULE_ICONS[module]}</span>
                                    <span>{MODULE_LABELS[module]}</span>
                                </div>
                                <span
                                    style={{
                                        fontWeight: "700",
                                        fontSize: "15px",
                                        color: license.borderColor,
                                    }}
                                >
                                    {getModuleLimit(licenseType, module)}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* دکمه‌ها */}
                <div style={{ display: "flex", gap: "12px" }}>
                    <button
                        onClick={onClose}
                        style={{
                            flex: 1,
                            padding: "11px",
                            borderRadius: "8px",
                            border: "1px solid #E5E7EB",
                            backgroundColor: "#ffffff",
                            color: "#374151",
                            fontSize: "14px",
                            fontWeight: "500",
                            cursor: "pointer",
                        }}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={() => onActivate(licenseType)}
                        style={{
                            flex: 1,
                            padding: "11px",
                            borderRadius: "8px",
                            border: "none",
                            backgroundColor: license.borderColor,
                            color: "#ffffff",
                            fontSize: "14px",
                            fontWeight: "600",
                            cursor: "pointer",
                        }}
                    >
                        Activate Licence
                    </button>
                </div>
            </div>
        </>
    );
};