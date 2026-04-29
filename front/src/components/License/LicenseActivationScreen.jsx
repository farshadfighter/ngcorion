import { useState, useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import { activateLicenseThunk, clearMessages } from "../../store/licenseSlice";

export const LicenseActivationScreen = () => {
    const dispatch = useDispatch();
    const { isActivating, error, isValid } = useSelector((state) => state.license);
    const [licenseKey, setLicenseKey] = useState("");

    // پاک کردن پیام‌های خطا بعد از 5 ثانیه
    useEffect(() => {
        if (error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 5000);
            return () => clearTimeout(timer);
        }
    }, [error, dispatch]);

    // اگر لایسنس فعال شد، صفحه را reload می‌کنیم
    useEffect(() => {
        if (isValid) {
            window.location.reload();
        }
    }, [isValid]);

    const handleActivate = () => {
        if (!licenseKey.trim()) return;
        dispatch(activateLicenseThunk(licenseKey.trim()));
    };

    const handleKeyPress = (e) => {
        if (e.key === 'Enter' && licenseKey.trim() && !isActivating) {
            handleActivate();
        }
    };

    return (
        <div
            style={{
                minHeight: "100vh",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                backgroundColor: "#F9FAFB",
                padding: "20px",
            }}
        >
            <div
                style={{
                    backgroundColor: "#ffffff",
                    borderRadius: "16px",
                    boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)",
                    padding: "48px",
                    maxWidth: "480px",
                    width: "100%",
                }}
            >
                {/* Logo/Title */}
                <div style={{ textAlign: "center", marginBottom: "32px" }}>
                    <div
                        style={{
                            fontSize: "32px",
                            fontWeight: "700",
                            color: "#111827",
                            marginBottom: "8px",
                        }}
                    >
                        Activate Your License
                    </div>
                    <div style={{ fontSize: "14px", color: "#6B7280" }}>
                        Enter the license key provided by your administrator
                    </div>
                </div>

                {/* Error Message */}
                {error && (
                    <div
                        style={{
                            padding: "12px 16px",
                            borderRadius: "8px",
                            marginBottom: "24px",
                            backgroundColor: "#FEF2F2",
                            border: "1px solid #FECACA",
                            color: "#DC2626",
                            fontSize: "14px",
                            textAlign: "center",
                        }}
                    >
                        {error}
                    </div>
                )}

                {/* License Key Input */}
                <div style={{ marginBottom: "24px" }}>
                    <label
                        style={{
                            display: "block",
                            fontSize: "14px",
                            fontWeight: "500",
                            color: "#374151",
                            marginBottom: "8px",
                        }}
                    >
                        License Key
                    </label>
                    <input
                        type="text"
                        placeholder="XXXX-XXXX-XXXX-XXXX"
                        value={licenseKey}
                        onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
                        onKeyPress={handleKeyPress}
                        disabled={isActivating}
                        maxLength={19}
                        style={{
                            width: "100%",
                            padding: "14px 16px",
                            borderRadius: "8px",
                            border: "2px solid #E5E7EB",
                            fontSize: "16px",
                            textAlign: "center",
                            letterSpacing: "3px",
                            fontFamily: "monospace",
                            fontWeight: "600",
                            outline: "none",
                            transition: "border-color 0.2s",
                            backgroundColor: isActivating ? "#F9FAFB" : "#ffffff",
                        }}
                        onFocus={(e) => {
                            e.target.style.borderColor = "#111827";
                        }}
                        onBlur={(e) => {
                            e.target.style.borderColor = "#E5E7EB";
                        }}
                    />
                </div>

                {/* Activate Button */}
                <button
                    onClick={handleActivate}
                    disabled={isActivating || !licenseKey.trim()}
                    style={{
                        width: "100%",
                        padding: "14px 24px",
                        borderRadius: "8px",
                        border: "none",
                        backgroundColor:
                            isActivating || !licenseKey.trim() ? "#D1D5DB" : "#111827",
                        color: "#ffffff",
                        fontSize: "16px",
                        fontWeight: "600",
                        cursor:
                            isActivating || !licenseKey.trim() ? "not-allowed" : "pointer",
                        transition: "background-color 0.2s",
                        marginBottom: "24px",
                    }}
                    onMouseEnter={(e) => {
                        if (!isActivating && licenseKey.trim()) {
                            e.target.style.backgroundColor = "#1F2937";
                        }
                    }}
                    onMouseLeave={(e) => {
                        if (!isActivating && licenseKey.trim()) {
                            e.target.style.backgroundColor = "#111827";
                        }
                    }}
                >
                    {isActivating ? (
                        <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "8px" }}>
                            <span
                                style={{
                                    width: "16px",
                                    height: "16px",
                                    border: "2px solid #ffffff",
                                    borderTopColor: "transparent",
                                    borderRadius: "50%",
                                    animation: "spin 0.6s linear infinite",
                                }}
                            />
                            Activating...
                        </span>
                    ) : (
                        "Activate License"
                    )}
                </button>

                {/* Help Text */}
                <div
                    style={{
                        padding: "16px",
                        borderRadius: "8px",
                        backgroundColor: "#F9FAFB",
                        border: "1px solid #E5E7EB",
                    }}
                >
                    <div
                        style={{
                            fontSize: "13px",
                            color: "#6B7280",
                            textAlign: "center",
                            lineHeight: "1.6",
                        }}
                    >
                        <strong style={{ color: "#374151" }}>Don't have a license key?</strong>
                        <br />
                        Contact your system administrator to obtain one.
                    </div>
                </div>
            </div>

            {/* CSS Animation */}
            <style>{`
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            `}</style>
        </div>
    );
};
