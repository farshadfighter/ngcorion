import React from "react";
import { useSelector } from "react-redux";

const moduleIcons = {
    hardening:      "fa-shield-halved",
    auditing:       "fa-clipboard-list",
    auto_discovery: "fa-magnifying-glass",
    asset:          "fa-box-archive",
};

const moduleNames = {
    hardening:      "Hardening",
    auditing:       "Auditing",
    auto_discovery: "Auto Discovery",
    asset:          "Asset List",
};

const LicenseBadge = ({ module }) => {
    const license = useSelector((state) => state.license);

    const limits     = license?.limits || {};
    const usage      = license?.usage  || {};
    const isUnlimited = license?.isUnlimited;

    const limitMap = {
        hardening:      { max: limits.max_hardens,    used: usage.used_hardens     },
        auditing:       { max: limits.max_audits,      used: usage.used_audits      },
        auto_discovery: { max: limits.max_discoveries, used: usage.used_discoveries },
        asset:          { max: limits.max_assets,      used: usage.used_assets      },
    };

    const moduleData  = limitMap[module] || { max: 0, used: 0 };
    const displayMax  = isUnlimited ? "∞" : (moduleData.max  ?? 0);
    const displayUsed = isUnlimited ? "∞" : (moduleData.used ?? 0);
    const displayName = moduleNames[module] || "Module";
    const iconClass   = moduleIcons[module] || "fa-circle-dot";

    return (
        <div style={{
            display: "flex",
            alignItems: "stretch",
            borderRadius: "10px",
            overflow: "hidden",
            border: "1px solid #d1d9e6",
            boxShadow: "0 1px 4px rgba(0,0,0,0.07)",
            height: "44px",
        }}>
            {/* سمت چپ - سفید */}
            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "0 16px",
                backgroundColor: "#ffffff",
                borderRight: "1px solid #d1d9e6",
            }}>
                <i
                    className="fa-solid fa-id-card"
                    style={{ fontSize: "15px", color: "#1d2939" }}
                />
                <span style={{
                    fontSize: "13px",
                    fontWeight: "700",
                    color: "#1d2939",
                    whiteSpace: "nowrap",
                    letterSpacing: "0.1px",
                }}>
                    Base Licence
                </span>
            </div>

            {/* سمت راست - آبی تیره */}
            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                padding: "0 16px",
                backgroundColor: "#0f2044",
            }}>
                <i
                    className={`fa-solid ${iconClass}`}
                    style={{ fontSize: "14px", color: "#7aaddb" }}
                />
                <div style={{ display: "flex", flexDirection: "column", lineHeight: "1.35" }}>
                    <span style={{
                        fontSize: "12px",
                        fontWeight: "500",
                        color: "#e6f1fb",
                        whiteSpace: "nowrap",
                        letterSpacing: "0.2px",
                    }}>
                        {displayName}
                    </span>
                    <span style={{
                        fontSize: "11px",
                        color: "#7aaddb",
                        fontVariantNumeric: "tabular-nums",
                    }}>
                        {displayUsed}/{displayMax}
                    </span>
                </div>
            </div>
        </div>
    );
};

export default LicenseBadge;