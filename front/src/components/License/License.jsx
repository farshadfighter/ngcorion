import { useState, useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import {
    activateLicenseThunk,
    getLicenseStatusThunk,
    clearMessages,
} from "../../store/licenseSlice";
import { LicenseCard } from "./LicenseCard";
import { LICENSE_TYPES, MODULE_LABELS, MODULE_ICONS, API_FIELD_MAP } from "./licenseConfig";

export const License = () => {
    const dispatch = useDispatch();
    const {
        isValid,
        planType,
        limits,
        usage,
        isActivating,
        isValidating,
        error,
        successMessage,
    } = useSelector((state) => state.license);

    const [licenseKey, setLicenseKey] = useState("");

    useEffect(() => {
        if (!isValid) return;
        const interval = setInterval(() => {
            dispatch(getLicenseStatusThunk());
        }, 5 * 60 * 1000);
        return () => clearInterval(interval);
    }, [isValid]);

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

    const buildApiData = () => {
        if (!usage || !limits) return null;
        return {
            used_hardens: usage?.used_hardens ?? 0,
            used_audits: usage?.used_audits ?? 0,
            max_hardens: limits?.max_hardens ?? null,
            max_audits: limits?.max_audits ?? null,
        };
    };

    const license = planType ? LICENSE_TYPES[planType] : null;
    const apiData = buildApiData();

    return (
        <div style={{
            padding: "32px 28px",
            maxWidth: "960px",
            margin: "0 auto",
            fontFamily: "'Segoe UI', sans-serif",
        }}>

            {/* Alert */}
            {(error || successMessage) && (
                <div style={{
                    padding: "14px 20px",
                    borderRadius: "10px",
                    marginBottom: "24px",
                    backgroundColor: error ? "#FEF2F2" : "#F0FDF4",
                    border: `1px solid ${error ? "#FECACA" : "#BBF7D0"}`,
                    color: error ? "#DC2626" : "#16A34A",
                    fontSize: "14px",
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                }}>
                    <span>{error ? "⚠️" : "✅"}</span>
                    {error || successMessage}
                </div>
            )}

            {/* ===== STATUS BOX ===== */}
            {isValidating ? (
                <div style={{
                    background: "linear-gradient(135deg, #1e3a5f 0%, #2d5a9e 100%)",
                    borderRadius: "16px",
                    padding: "40px",
                    textAlign: "center",
                    marginBottom: "40px",
                    color: "white",
                }}>
                    <div style={{ fontSize: "32px", marginBottom: "12px" }}>⏳</div>
                    <div style={{ fontSize: "16px", opacity: 0.9 }}>Checking licence status...</div>
                </div>
            ) : isValid && license ? (
                /* ---- دارای لایسنس ---- */
                <div style={{
                    background: "linear-gradient(135deg, #1e3a5f 0%, #2d5a9e 100%)",
                    borderRadius: "20px",
                    padding: "36px 40px",
                    marginBottom: "48px",
                    color: "white",
                    boxShadow: "0 20px 60px rgba(30, 58, 95, 0.3)",
                    position: "relative",
                    overflow: "hidden",
                }}>
                    {/* دایره دکوراتیو پس زمینه */}
                    <div style={{
                        position: "absolute", top: "-60px", right: "-60px",
                        width: "200px", height: "200px",
                        borderRadius: "50%",
                        background: "rgba(255,255,255,0.05)",
                        pointerEvents: "none",
                    }} />
                    <div style={{
                        position: "absolute", bottom: "-40px", left: "30%",
                        width: "140px", height: "140px",
                        borderRadius: "50%",
                        background: "rgba(255,255,255,0.04)",
                        pointerEvents: "none",
                    }} />

                    {/* هدر باکس */}
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "32px", flexWrap: "wrap", gap: "16px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                            {/* Frosted tile on the navy card; the icon is painted
                                white via brightness(0) invert(1) so it never
                                depends on the SVG's own fill. */}
                            <div style={{
                                width: "56px", height: "56px",
                                borderRadius: "14px",
                                backgroundColor: "rgba(255,255,255,0.16)",
                                border: "1px solid rgba(255,255,255,0.28)",
                                display: "flex", alignItems: "center", justifyContent: "center",
                                flexShrink: 0,
                            }}>
                                <img
                                    src="/icons/license.svg"
                                    alt=""
                                    style={{
                                        width: "28px", height: "28px",
                                        filter: "brightness(0) invert(1)",
                                    }}
                                />
                            </div>
                            <div>
                                <div style={{ fontSize: "13px", opacity: 0.7, marginBottom: "4px", letterSpacing: "0.5px" }}>
                                    ACTIVE LICENCE
                                </div>
                                <div style={{ fontSize: "22px", fontWeight: "700", letterSpacing: "-0.3px" }}>
                                    {license.name}
                                </div>
                            </div>
                        </div>

                        <div style={{
                            backgroundColor: "rgba(255,255,255,0.15)",
                            borderRadius: "30px",
                            padding: "8px 20px",
                            fontSize: "13px",
                            fontWeight: "600",
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            backdropFilter: "blur(4px)",
                        }}>
                            ✅ Active
                        </div>
                    </div>

                    {/* usage ماژول‌ها */}
                    <div style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                        gap: "12px",
                    }}>
                        {Object.keys(MODULE_LABELS).map((module) => {
                            const { used: usedKey, max: maxKey } = API_FIELD_MAP[module];
                            const usedValue = apiData ? apiData[usedKey] ?? 0 : 0;
                            const maxValue = apiData ? apiData[maxKey] : null;
                            const displayMax = maxValue === null ? "∞" : maxValue;
                            const percent = maxValue ? Math.min((usedValue / maxValue) * 100, 100) : 0;
                            const isNearLimit = maxValue && usedValue >= maxValue * 0.8;

                            return (
                                <div key={module} style={{
                                    backgroundColor: "rgba(255,255,255,0.1)",
                                    borderRadius: "12px",
                                    padding: "16px",
                                    backdropFilter: "blur(4px)",
                                    border: "1px solid rgba(255,255,255,0.15)",
                                }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
                                        <i className={`fa-solid ${MODULE_ICONS[module]}`} style={{ fontSize: "16px", opacity: 0.85 }} />                                        <span style={{ fontSize: "13px", opacity: 0.85, fontWeight: "500" }}>
                                            {MODULE_LABELS[module]}
                                        </span>
                                    </div>
                                    <div style={{ fontSize: "20px", fontWeight: "700", marginBottom: "8px" }}>
                                        {usedValue}
                                        <span style={{ fontSize: "14px", opacity: 0.7, fontWeight: "400" }}>
                                            /{displayMax}
                                        </span>
                                    </div>
                                    {maxValue && (
                                        <div style={{
                                            height: "4px",
                                            backgroundColor: "rgba(255,255,255,0.2)",
                                            borderRadius: "2px",
                                            overflow: "hidden",
                                        }}>
                                            <div style={{
                                                width: `${percent}%`,
                                                height: "100%",
                                                backgroundColor: isNearLimit ? "#FCA5A5" : "#86EFAC",
                                                borderRadius: "2px",
                                                transition: "width 0.5s ease",
                                            }} />
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            ) : (
                /* ---- بدون لایسنس ---- */
                <div style={{
                    background: "linear-gradient(135deg, #1f2937 0%, #374151 100%)",
                    borderRadius: "20px",
                    padding: "40px",
                    marginBottom: "48px",
                    color: "white",
                    boxShadow: "0 20px 60px rgba(0,0,0,0.2)",
                    position: "relative",
                    overflow: "hidden",
                }}>
                    <div style={{
                        position: "absolute", top: "-40px", right: "-40px",
                        width: "160px", height: "160px",
                        borderRadius: "50%",
                        background: "rgba(255,255,255,0.04)",
                        pointerEvents: "none",
                    }} />

                    <div style={{ display: "flex", alignItems: "flex-start", gap: "24px", flexWrap: "wrap" }}>
                        {/* سمت چپ: وضعیت و فرم */}
                        <div style={{ flex: 1, minWidth: "260px" }}>
                            <div style={{
                                display: "inline-flex", alignItems: "center", gap: "8px",
                                backgroundColor: "rgba(239,68,68,0.2)",
                                border: "1px solid rgba(239,68,68,0.4)",
                                borderRadius: "30px",
                                padding: "6px 16px",
                                fontSize: "13px",
                                color: "#FCA5A5",
                                marginBottom: "20px",
                            }}>
                                <i className="fa-solid fa-lock" style={{ marginRight: "6px" }} />
                                No Active Licence
                            </div>
                            <div style={{ fontSize: "22px", fontWeight: "700", marginBottom: "8px" }}>
                                Activate Your Licence
                            </div>
                            <div style={{ fontSize: "14px", opacity: 0.7, marginBottom: "28px", lineHeight: "1.6" }}>
                                Enter your licence key below to unlock full access to all features.
                            </div>

                            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                                <input
                                    type="text"
                                    placeholder="XXXX-XXXX-XXXX-XXXX"
                                    value={licenseKey}
                                    onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
                                    disabled={isActivating}
                                    maxLength={19}
                                    style={{
                                        flex: 1,
                                        minWidth: "200px",
                                        padding: "12px 16px",
                                        borderRadius: "10px",
                                        border: "1px solid rgba(255,255,255,0.2)",
                                        backgroundColor: "rgba(255,255,255,0.08)",
                                        color: "white",
                                        fontSize: "15px",
                                        textAlign: "center",
                                        letterSpacing: "3px",
                                        fontFamily: "monospace",
                                        fontWeight: "600",
                                        outline: "none",
                                    }}
                                />
                                <button
                                    onClick={handleActivate}
                                    disabled={isActivating || !licenseKey.trim()}
                                    style={{
                                        padding: "12px 28px",
                                        borderRadius: "10px",
                                        border: "none",
                                        backgroundColor: isActivating || !licenseKey.trim() ? "rgba(255,255,255,0.1)" : "#3B82F6",
                                        color: "white",
                                        fontSize: "14px",
                                        fontWeight: "700",
                                        cursor: isActivating || !licenseKey.trim() ? "not-allowed" : "pointer",
                                        whiteSpace: "nowrap",
                                        transition: "all 0.2s",
                                    }}
                                >
                                    {isActivating ? "⏳ Activating...": "Activate"}
                                </button>
                            </div>

                            <div style={{ marginTop: "16px", fontSize: "12px", opacity: 0.5 }}>
                                Don't have a key? Contact your system administrator.
                            </div>
                        </div>

                        {/* سمت راست: تعرفه رایگان */}
                        <div style={{
                            backgroundColor: "rgba(255,255,255,0.07)",
                            borderRadius: "14px",
                            padding: "20px 24px",
                            border: "1px solid rgba(255,255,255,0.12)",
                            minWidth: "200px",
                        }}>
                            <div style={{ fontSize: "13px", opacity: 0.6, marginBottom: "12px", fontWeight: "600", letterSpacing: "0.5px" }}>
                                <i className="fa-solid fa-gift" /> FREE PILOT PLAN
                            </div>
                            {Object.keys(MODULE_LABELS).map((module) => {
                                const pilotLimit = LICENSE_TYPES.pilot?.limits[module];
                                return (
                                    <div key={module} style={{
                                        display: "flex", alignItems: "center", justifyContent: "space-between",
                                        marginBottom: "10px", gap: "16px",
                                    }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", opacity: 0.8 }}>
                                            <span>{MODULE_ICONS[module]}</span>
                                            <span>{MODULE_LABELS[module]}</span>
                                        </div>
                                        <span style={{
                                            fontWeight: "700", fontSize: "14px",
                                            color: "#86EFAC",
                                        }}>
                                            {pilotLimit === Infinity ? "∞" : pilotLimit}
                                        </span>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </div>
            )}

            {/* ===== عنوان بخش تعرفه‌ها ===== */}
            <div style={{ marginBottom: "24px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
                    <div style={{
                        width: "4px", height: "28px",
                        backgroundColor: "#1e3a5f",
                        borderRadius: "2px",
                    }} />
                    <h2 style={{ margin: 0, fontSize: "20px", fontWeight: "700", color: "#111827" }}>
                        Available Licence Plans
                    </h2>
                </div>
                <p style={{ margin: "0 0 0 16px", fontSize: "14px", color: "#6B7280", paddingLeft: "16px" }}>
                    Choose the plan that fits your organization's needs
                </p>
            </div>

            {/* ===== کارت‌های تعرفه ===== */}
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                {Object.keys(LICENSE_TYPES).map((type) => (
                    <LicenseCard
                        key={type}
                        licenseType={type}
                        isActive={planType === type}
                        apiData={planType === type ? apiData : null}
                    />
                ))}
            </div>

            {/* فوتر */}
            <div style={{
                marginTop: "48px",
                padding: "20px",
                borderTop: "1px solid #E5E7EB",
                textAlign: "center",
                fontSize: "13px",
                color: "#9CA3AF",
            }}>
                <i className="fa-solid fa-shield-halved" style={{ marginRight: "6px" }} />
                All licence operations are secured and validated against your server
            </div>
        </div>
    );
};