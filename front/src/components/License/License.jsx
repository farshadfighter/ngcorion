import { useState, useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import {
    activateLicenseThunk,
    validateLicenseThunk,
    heartbeatThunk,
    clearMessages,
    initializeFromStorage,
} from "../../store/licenseSlice";
import { LicenseCard } from "./LicenseCard";
import { LicenseHeader } from "./LicenseHeader";
import { LicenseModal } from "./LicenseModal";
import { LICENSE_TYPES } from "./licenseConfig";
import { loadLicenseFromStorage } from "./licenseService";

export const License = () => {
    const dispatch = useDispatch();
    const {
        isValid,
        planType,
        isPilotMode,
        limits,
        usage,
        isActivating,
        isValidating,
        error,
        successMessage,
        isInitialized,
    } = useSelector((state) => state.license);

    const [activeTab, setActiveTab] = useState("active");
    const [licenseKey, setLicenseKey] = useState("");
    const [selectedPlan, setSelectedPlan] = useState(null);
    const [showModal, setShowModal] = useState(false);

    // اول از storage لود میکنیم
    useEffect(() => {
        dispatch(initializeFromStorage());
    }, []);

    // اگه storage داشت validate میکنیم
    useEffect(() => {
        if (isInitialized) {
            const stored = loadLicenseFromStorage();
            if (stored) {
                dispatch(validateLicenseThunk());
            }
        }
    }, [isInitialized]);

    // heartbeat هر ساعت
    useEffect(() => {
        if (!isValid) return;

        const interval = setInterval(() => {
            dispatch(heartbeatThunk());
        }, 60 * 60 * 1000);

        return () => clearInterval(interval);
    }, [isValid]);

    // پاک کردن پیام‌ها
    useEffect(() => {
        if (error || successMessage) {
            const timer = setTimeout(() => dispatch(clearMessages()), 4000);
            return () => clearTimeout(timer);
        }
    }, [error, successMessage]);

    const handleActivate = async () => {
        if (!licenseKey.trim()) return;
        dispatch(activateLicenseThunk(licenseKey.trim()));
    };

    const handlePlanClick = (planType) => {
        setSelectedPlan(planType);
        setShowModal(true);
    };

    // ساخت apiData از اطلاعات redux
    const buildApiData = () => {
        if (!usage || !limits) return null;
        return {
            used_hardens: usage?.used_hardens ?? 0,
            used_audits: usage?.used_audits ?? 0,
            used_assets: usage?.used_assets ?? 0,
            used_discoveries: usage?.used_discoveries ?? 0,
            max_hardens: limits?.max_hardens ?? null,
            max_audits: limits?.max_audits ?? null,
            max_assets: limits?.max_assets ?? null,
            max_discoveries: limits?.max_discoveries ?? null,
        };
    };

    return (
        <div style={{ padding: "24px", maxWidth: "900px", margin: "0 auto" }}>

            {/* پیام‌های success/error */}
            {(error || successMessage) && (
                <div
                    style={{
                        padding: "12px 20px",
                        borderRadius: "8px",
                        marginBottom: "20px",
                        backgroundColor: error ? "#FEF2F2" : "#F0FDF4",
                        border: `1px solid ${error ? "#FECACA" : "#BBF7D0"}`,
                        color: error ? "#DC2626" : "#16A34A",
                        fontSize: "14px",
                    }}
                >
                    {error || successMessage}
                </div>
            )}

            {/* تب‌ها */}
            <div style={{ display: "flex", gap: "8px", marginBottom: "28px" }}>
                {["active", "available"].map((tab) => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        style={{
                            padding: "10px 24px",
                            borderRadius: "8px",
                            border: "none",
                            cursor: "pointer",
                            fontSize: "14px",
                            fontWeight: "500",
                            backgroundColor: activeTab === tab ? "#111827" : "#F3F4F6",
                            color: activeTab === tab ? "#ffffff" : "#6B7280",
                            transition: "all 0.2s",
                        }}
                    >
                        {tab === "active" ? "Active licence" : "Available licences"}
                    </button>
                ))}
            </div>

            {/* تب Active */}
            {activeTab === "active" && (
                <div>
                    {isValidating && (
                        <div style={{ textAlign: "center", padding: "40px", color: "#6B7280" }}>
                            Validating licence...
                        </div>
                    )}

                    {!isValidating && isValid && planType && (
                        <>
                            {/* هدر لایسنس فعال */}
                            <LicenseHeader
                                licenseType={planType}
                                apiData={buildApiData()}
                            />

                            {/* کارت لایسنس فعال */}
                            <LicenseCard
                                licenseType={planType}
                                isActive={true}
                                apiData={buildApiData()}
                            />
                        </>
                    )}

                    {!isValidating && !isValid && (
                        <div
                            style={{
                                backgroundColor: "#ffffff",
                                border: "1px solid #E5E7EB",
                                borderRadius: "12px",
                                padding: "40px",
                                textAlign: "center",
                            }}
                        >
                            <div style={{ fontSize: "48px", marginBottom: "16px" }}>🪪</div>
                            <div style={{ fontSize: "18px", fontWeight: "600", color: "#111827", marginBottom: "8px" }}>
                                No Active Licence
                            </div>
                            <div style={{ fontSize: "14px", color: "#6B7280", marginBottom: "28px" }}>
                                Enter your licence key to activate
                            </div>

                            {/* فرم فعال‌سازی */}
                            <div style={{ display: "flex", gap: "10px", maxWidth: "480px", margin: "0 auto" }}>
                                <input
                                    type="text"
                                    value={licenseKey}
                                    onChange={(e) => setLicenseKey(e.target.value)}
                                    placeholder="XXXX-XXXX-XXXX-XXXX"
                                    onKeyDown={(e) => e.key === "Enter" && handleActivate()}
                                    style={{
                                        flex: 1,
                                        padding: "10px 16px",
                                        borderRadius: "8px",
                                        border: "1px solid #E5E7EB",
                                        fontSize: "14px",
                                        outline: "none",
                                        letterSpacing: "1px",
                                    }}
                                />
                                <button
                                    onClick={handleActivate}
                                    disabled={isActivating || !licenseKey.trim()}
                                    style={{
                                        padding: "10px 24px",
                                        borderRadius: "8px",
                                        border: "none",
                                        backgroundColor: isActivating || !licenseKey.trim() ? "#D1D5DB" : "#111827",
                                        color: "#ffffff",
                                        fontSize: "14px",
                                        fontWeight: "600",
                                        cursor: isActivating || !licenseKey.trim() ? "not-allowed" : "pointer",
                                    }}
                                >
                                    {isActivating ? "Activating..." : "Activate"}
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* تب Available */}
            {activeTab === "available" && (
                <div>
                    <div style={{ fontSize: "13px", color: "#6B7280", marginBottom: "20px" }}>
                        Available licence plans:
                    </div>
                    {Object.keys(LICENSE_TYPES).map((type) => (
                        <LicenseCard
                            key={type}
                            licenseType={type}
                            isActive={planType === type}
                            onActivate={!isValid ? handlePlanClick : undefined}
                        />
                    ))}
                </div>
            )}

            {/* مودال */}
            {showModal && selectedPlan && (
                <LicenseModal
                    licenseType={selectedPlan}
                    onClose={() => {
                        setShowModal(false);
                        setSelectedPlan(null);
                    }}
                    onActivate={(type) => {
                        setShowModal(false);
                        setSelectedPlan(null);
                        setActiveTab("active");
                    }}
                />
            )}
        </div>
    );
};