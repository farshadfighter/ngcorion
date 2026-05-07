import React from "react";
import { useSelector } from "react-redux";

const LicenseBadge = ({ module }) => {
    const license = useSelector((state) => state.license);

    const limits = license?.limits || {};
    const usage  = license?.usage  || {};
    const isUnlimited = license?.isUnlimited;

    const limitMap = {
        hardening:      { max: limits.max_hardens,     used: usage.used_hardens     },
        auditing:       { max: limits.max_audits,       used: usage.used_audits       },
        auto_discovery: { max: limits.max_discoveries,  used: usage.used_discoveries  },
        asset:          { max: limits.max_assets,       used: usage.used_assets       },
    };

    const moduleData  = limitMap[module] || { max: 0, used: 0 };
    const displayMax  = isUnlimited ? "∞" : (moduleData.max  ?? 0);
    const displayUsed = isUnlimited ? "∞" : (moduleData.used ?? 0);

    const moduleNames = {
        hardening:      "Hardening",
        auditing:       "Auditing",
        auto_discovery: "Auto Discovery",
        asset:          "Asset List",
    };
    const displayName = moduleNames[module] || "Module";

    return (
        <div style={{
            display: "flex",
            alignItems: "stretch",
            borderRadius: "10px",
            overflow: "hidden",
            border: "1px solid #e2e8f0",
            boxShadow: "0 1px 4px rgba(0,0,0,0.08)",
            height: "40px",
        }}>
            {/* سمت چپ - سفید */}
            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "0 14px",
                backgroundColor: "#ffffff",
                borderRight: "1px solid #e2e8f0",
            }}>
                <img
                    src="/icons/headlicense.svg"
                    alt="license"
                    style={{ width: "16px", height: "16px" }}
                />
                <span style={{
                    fontSize: "13px",
                    fontWeight: "500",
                    color: "#1d2939",
                    whiteSpace: "nowrap",
                }}>
                    base licence
                </span>
            </div>

            {/* سمت راست - آبی تیره */}
            <div style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "0 14px",
                backgroundColor: "#0f2044",
            }}>
                <i className="ti ti-search" style={{ fontSize: "15px", color: "#7aaddb" }} />

                <div style={{ display: "flex", flexDirection: "column", lineHeight: "1.3" }}>
                    <span style={{
                        fontSize: "12px",
                        fontWeight: "600",
                        color: "#e6f1fb",
                        whiteSpace: "nowrap",
                    }}>
                        {displayName}
                    </span>
                    <span style={{ fontSize: "11px", color: "#7aaddb" }}>
                        {displayUsed}/{displayMax}
                    </span>
                </div>
            </div>
        </div>
    );
};

export default LicenseBadge;