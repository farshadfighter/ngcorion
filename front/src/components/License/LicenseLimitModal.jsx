import { LICENSE_TYPES } from "./licenseConfig";
import { useSelector } from "react-redux";

export const LicenseLimitModal = ({ isOpen, module, onClose, onGoToLicence }) => {
    const { planType } = useSelector((state) => state.license);
    const license = LICENSE_TYPES[planType];

    if (!isOpen) return null;
    // Asset Management is not license-gated, so it has no entry here.
    const MODULE_LABELS = {
        auditing: "Auditing",
        hardening: "Hardening",
    };

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
            <div style={{
                position: "fixed",
                top: "50%",
                left: "50%",
                transform: "translate(-50%, -50%)",
                backgroundColor: "#ffffff",
                borderRadius: "16px",
                padding: "32px",
                zIndex: 1001,
                width: "420px",
                maxWidth: "90vw",
                boxShadow: "0 20px 60px rgba(0,0,0,0.15)",
                borderTop: "4px solid #EF4444",
                textAlign: "center",
            }}>
                {/* آیکون */}
                <div style={{
                    width: "64px",
                    height: "64px",
                    backgroundColor: "#FEF2F2",
                    borderRadius: "50%",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: "28px",
                    margin: "0 auto 20px",
                }}>
                    <i className="fa-solid fa-ban" />
                </div>

                {/* عنوان */}
                <div style={{ fontSize: "18px", fontWeight: "700", color: "#111827", marginBottom: "8px" }}>
                    {MODULE_LABELS[module]} Limit Reached
                </div>

                {/* توضیح */}
                <div style={{ fontSize: "14px", color: "#6B7280", marginBottom: "8px" }}>
                    You have reached the maximum limit for <strong>{MODULE_LABELS[module]}</strong> operations on your
                </div>

                {/* نام لایسنس */}
                {license && (
                    <div style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        backgroundColor: license.bgColor,
                        border: `1px solid ${license.borderColor}`,
                        borderRadius: "6px",
                        padding: "4px 12px",
                        fontSize: "13px",
                        fontWeight: "600",
                        color: license.borderColor,
                        marginBottom: "24px",
                    }}>
                        <i className="fa-solid fa-circle-exclamation"
                           style={{ marginRight: "8px" }} />
                        {license.name}
                    </div>
                )}

                <div style={{ fontSize: "13px", color: "#9CA3AF", marginBottom: "28px" }}>
                    Please upgrade your licence to continue using this feature.
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
                        onClick={onGoToLicence}
                        style={{
                            flex: 1,
                            padding: "11px",
                            borderRadius: "8px",
                            border: "none",
                            backgroundColor: "#1e3a5f",
                            color: "#ffffff",
                            fontSize: "14px",
                            fontWeight: "600",
                            cursor: "pointer",
                        }}
                    >
                        Go to Licence
                    </button>
                </div>
            </div>
        </>
    );
};