import React from "react";
import { useSelector } from "react-redux";

const LicenseBadge = ({ module }) => {
    const license = useSelector((state) => state.license);

    // دریافت محدودیت‌ها از ریداکس
    const limits = license?.limits || {};
    const isUnlimited = license?.isUnlimited;

    // مپ کردن نام ماژول پاس داده شده به کلیدهای داخل ریداکس
    const limitMap = {
        hardening: limits.maxHardeningAsset,
        auditing: limits.maxAuditingAsset,
        auto_discovery: limits.maxNetworkDiscoveryAsset,
        asset: limits.maxAsset,
    };

    // تعیین ظرفیت کل ماژول فعال
    const maxVal = limitMap[module];
    const displayMax = isUnlimited ? "∞" : maxVal || 0;

    // نام نمایشی ماژول‌ها برای کاربر
    const moduleNames = {
        hardening: "Hardening",
        auditing: "Auditing",
        auto_discovery: "Auto Discovery",
        asset: "Asset List",
    };

    const displayName = moduleNames[module] || "Module";

    return (
        <div
            className="license-badge-container"
            style={{
                display: "flex",
                alignItems: "center",
                backgroundColor: "#1E293B", // پس زمینه کلی (کمی روشن‌تر از مشکی)
                borderRadius: "12px",
                padding: "4px",
                border: "1px solid #334155",
                gap: "12px",
                height: "48px",
                boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
            }}
        >
            {/* بخش سمت چپ: ثابت (آیکون + نام بیس لایسنس) */}
            <div
                className="license-badge-left"
                style={{
                    display: "flex",
                    alignItems: "center",
                    backgroundColor: "#0F172A", // پس زمینه تیره‌تر برای بخش چپ
                    padding: "6px 12px",
                    borderRadius: "8px",
                    gap: "8px",
                    height: "100%",
                }}
            >
        <span
            style={{
                backgroundColor: "#1E293B",
                padding: "6px",
                borderRadius: "6px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
            }}
        >
          <img
              src="/icons/headlicense.svg"
              alt="license icon"
              style={{ width: "16px", height: "16px" }}
          />
        </span>
                <span
                    style={{
                        color: "#94A3B8", // رنگ خاکستری روشن برای متن
                        fontSize: "13px",
                        fontWeight: "500",
                        whiteSpace: "nowrap",
                    }}
                >
          base licence
        </span>
            </div>

            {/* بخش سمت راست: داینامیک (نام ماژول + تعداد کل) */}
            <div
                className="license-badge-right"
                style={{
                    display: "flex",
                    flexDirection: "column", // قرارگیری نام و عدد زیر هم
                    alignItems: "flex-start",
                    justifyContent: "center",
                    paddingRight: "16px",
                }}
            >
        <span
            style={{
                color: "#F8FAFC", // رنگ سفید برای نام ماژول
                fontSize: "13px",
                fontWeight: "600",
                lineHeight: "1.2",
            }}
        >
          {displayName}
        </span>
                <span
                    style={{
                        color: "#38BDF8", // رنگ آبی/متفاوت برای نمایش عدد کل
                        fontSize: "14px",
                        fontWeight: "700",
                        lineHeight: "1.2",
                    }}
                >
          {displayMax}
        </span>
            </div>
        </div>
    );
};

export default LicenseBadge;
