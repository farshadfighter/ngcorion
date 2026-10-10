/**
 * License page: the installed license (plan, assets used against its limit,
 * add-ons, term, contact with the license server), activation when there is
 * none, and the plans NGCorion is sold in.
 *
 * Everything shown about this installation comes from the backend
 * (GET /api/license/status and /api/license/usage); the plan list below is a
 * catalog for reference only.
 */
import { useState, useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import {
    activateLicenseThunk,
    getLicenseStatusThunk,
    getLicenseUsageThunk,
    clearMessages,
} from "../../store/licenseSlice";
import { LicenseCard } from "./LicenseCard";
import { OfflineActivation } from "./OfflineActivation";
import { ADDON, OFFLINE_GRACE_HOURS, PILOT, PLANS, planLabel } from "./licenseConfig";
import { t, n, uiLocale } from "../../i18n";
import { tx } from "../../i18n/tx";

// The API sends UTC times without a zone suffix.
const asDate = (value) => (value ? new Date(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`) : null);

const fmtDate = (value, withTime = false) => {
    const d = asDate(value);
    if (!d || Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString(uiLocale(), withTime
        ? { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" }
        : { year: "numeric", month: "long", day: "numeric" });
};

const Banner = ({ tone, icon, title, children }) => {
    const tones = {
        warn: { bg: "#FFFBEB", border: "#FDE68A", color: "#92400E" },
        danger: { bg: "#FEF2F2", border: "#FECACA", color: "#991B1B" },
        info: { bg: "#EFF6FF", border: "#BFDBFE", color: "#1E40AF" },
    }[tone];
    return (
        <div role="status" style={{
            display: "flex", gap: "14px", alignItems: "flex-start",
            padding: "16px 20px", borderRadius: "12px", marginBottom: "20px",
            backgroundColor: tones.bg, border: `1px solid ${tones.border}`, color: tones.color,
        }}>
            <i className={`fa-solid ${icon}`} style={{ fontSize: "18px", marginTop: "2px" }} />
            <div style={{ fontSize: "14px", lineHeight: 1.7 }}>
                <div style={{ fontWeight: 700, marginBottom: "2px" }}>{title}</div>
                {children}
            </div>
        </div>
    );
};

const Stat = ({ label, value, sub }) => (
    <div style={{
        backgroundColor: "rgba(255,255,255,0.1)", borderRadius: "12px", padding: "14px 16px",
        border: "1px solid rgba(255,255,255,0.15)", minWidth: 0,
    }}>
        <div style={{ fontSize: "12px", opacity: 0.75, marginBottom: "6px" }}>{label}</div>
        <div style={{ fontSize: "17px", fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{value}</div>
        {sub && <div style={{ fontSize: "12px", opacity: 0.7, marginTop: "4px" }}>{sub}</div>}
    </div>
);

export const License = () => {
    const dispatch = useDispatch();
    const {
        isValid, planCode, planName, isPilotMode, maxAssets, addonPacks, expiresAt,
        lastContactAt, offline, offlinePilot, offlinePilotUntil, offlineLicense, offlineUntil, usage,
        isActivating, isValidating, error, successMessage,
    } = useSelector((state) => state.license);

    const [licenseKey, setLicenseKey] = useState("");
    // "Now" for the days left of an offline license file: taken once, when the page opens.
    const [openedAt] = useState(() => Date.now());

    useEffect(() => {
        if (!isValid) return;
        dispatch(getLicenseUsageThunk());
        const interval = setInterval(() => {
            dispatch(getLicenseStatusThunk());
            dispatch(getLicenseUsageThunk());
        }, 5 * 60 * 1000);
        return () => clearInterval(interval);
    }, [isValid, dispatch]);

    useEffect(() => {
        if (error || successMessage) {
            const timer = setTimeout(() => dispatch(clearMessages()), 4000);
            return () => clearTimeout(timer);
        }
    }, [error, successMessage, dispatch]);

    const handleActivate = () => {
        if (!licenseKey.trim()) return;
        dispatch(activateLicenseThunk(licenseKey.trim()));
    };

    const used = usage?.used ?? null;
    const unlimited = maxAssets === null || maxAssets === undefined;
    const percent = !unlimited && maxAssets > 0 && used !== null ? Math.min((used / maxAssets) * 100, 100) : 0;
    const overLimit = !!usage?.over_limit;
    const offlineDaysLeft = offlineUntil ? Math.floor((asDate(offlineUntil).getTime() - openedAt) / 86400000) : null;
    const graceEnds = lastContactAt ? new Date(asDate(lastContactAt).getTime() + OFFLINE_GRACE_HOURS * 3600 * 1000) : null;

    return (
        <div style={{ padding: "32px 28px", maxWidth: "980px", margin: "0 auto", fontFamily: "var(--font-sans)" }}>

            {(error || successMessage) && (
                <div style={{
                    padding: "14px 20px", borderRadius: "10px", marginBottom: "24px",
                    backgroundColor: error ? "#FEF2F2" : "#F0FDF4",
                    border: `1px solid ${error ? "#FECACA" : "#BBF7D0"}`,
                    color: error ? "#DC2626" : "#16A34A", fontSize: "14px",
                }}>
                    {error || successMessage}
                </div>
            )}

            {isValid && offlinePilot && (
                <Banner tone="warn" icon="fa-plug-circle-exclamation" title={t("Running as a pilot license")}>
                    {tx("NGCorion has not reached the license server for more than {{hours}} hours, so it runs as a pilot license with {{assets}} assets until {{date}}. Your plan returns as soon as the license server is reached again.", {
                        hours: OFFLINE_GRACE_HOURS, assets: PILOT.assets, date: fmtDate(offlinePilotUntil, true),
                    })}
                </Banner>
            )}
            {isValid && offlineLicense && offlineDaysLeft !== null && offlineDaysLeft <= 30 && (
                <Banner tone="warn" icon="fa-hourglass-half" title={t("The offline license file ends soon")}>
                    {tx("It ends on {{date}} ({{days}} days left). Renew it below: download a request file and upload the new license file.", {
                        date: fmtDate(offlineUntil), days: Math.max(offlineDaysLeft, 0),
                    })}
                </Banner>
            )}
            {isValid && offline && !offlinePilot && !offlineLicense && (
                <Banner tone="info" icon="fa-wifi" title={t("The license server cannot be reached")}>
                    {tx("The license keeps working as it is until {{date}}. After that, without contact, NGCorion runs as a pilot license ({{assets}} assets) for {{days}} days.", {
                        date: fmtDate(graceEnds, true), assets: PILOT.assets, days: PILOT.days,
                    })}
                </Banner>
            )}
            {isValid && overLimit && (
                <Banner tone="danger" icon="fa-triangle-exclamation" title={t("More assets than the license covers")}>
                    {tx("The inventory has {{used}} assets and the license covers {{limit}}. Audits and hardening run only on the first {{limit}} assets (the oldest); the others stay in the inventory. Remove assets you no longer need, or extend the license with add-on packs of {{addon}} assets.", {
                        used, limit: maxAssets, addon: ADDON.assets,
                    })}
                </Banner>
            )}

            {/* ===== STATUS ===== */}
            {isValidating && !isValid ? (
                <div style={{
                    background: "linear-gradient(135deg, #1e3a5f 0%, #2d5a9e 100%)", borderRadius: "16px",
                    padding: "40px", textAlign: "center", marginBottom: "40px", color: "white",
                }}>
                    <div style={{ fontSize: "16px", opacity: 0.9 }}>{t("Checking licence status...")}</div>
                </div>
            ) : isValid ? (
                <div style={{
                    background: offlinePilot
                        ? "linear-gradient(135deg, #78350F 0%, #B45309 100%)"
                        : "linear-gradient(135deg, #1e3a5f 0%, #2d5a9e 100%)",
                    borderRadius: "20px", padding: "32px 36px", marginBottom: "48px", color: "white",
                    boxShadow: "0 20px 60px rgba(30, 58, 95, 0.3)",
                }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "26px", flexWrap: "wrap", gap: "16px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "16px", minWidth: 0 }}>
                            <div style={{
                                width: "56px", height: "56px", borderRadius: "14px", flexShrink: 0,
                                backgroundColor: "rgba(255,255,255,0.16)", border: "1px solid rgba(255,255,255,0.28)",
                                display: "flex", alignItems: "center", justifyContent: "center",
                            }}>
                                <img src="/icons/license.svg" alt="" style={{ width: "28px", height: "28px", filter: "brightness(0) invert(1)" }} />
                            </div>
                            <div style={{ minWidth: 0 }}>
                                <div style={{ fontSize: "13px", opacity: 0.7, marginBottom: "4px", letterSpacing: "0.5px" }}>
                                    {t("ACTIVE LICENCE")}
                                </div>
                                <div style={{ fontSize: "22px", fontWeight: 700 }}>
                                    {planLabel(planCode, planName)}
                                    {addonPacks > 0 && (
                                        <span style={{ fontSize: "15px", fontWeight: 500, opacity: 0.85 }}>
                                            {" "}{tx("+ {{count}} add-on packs", { count: addonPacks })}
                                        </span>
                                    )}
                                </div>
                                <div style={{ fontSize: "12px", opacity: 0.65, fontFamily: "monospace", marginTop: "2px" }} dir="ltr">
                                    {planCode}
                                </div>
                            </div>
                        </div>
                        <div style={{
                            backgroundColor: "rgba(255,255,255,0.15)", borderRadius: "30px", padding: "8px 18px",
                            fontSize: "13px", fontWeight: 600,
                        }}>
                            {offlinePilot ? t("Pilot (offline)") : offlineLicense ? t("Offline license") : isPilotMode ? t("Pilot licence") : t("✅ Active")}
                        </div>
                    </div>

                    {/* Assets used against the limit */}
                    <div style={{ marginBottom: "18px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "14px", marginBottom: "8px", gap: "12px" }}>
                            <span style={{ opacity: 0.85 }}>{t("Assets")}</span>
                            <span style={{ fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>
                                {used === null ? "—" : n(used)} / {unlimited ? t("Unlimited") : n(maxAssets)}
                            </span>
                        </div>
                        {!unlimited && (
                            <div style={{ height: "8px", backgroundColor: "rgba(255,255,255,0.2)", borderRadius: "4px", overflow: "hidden" }}>
                                <div style={{
                                    width: `${percent}%`, height: "100%", borderRadius: "4px", transition: "width 0.5s ease",
                                    backgroundColor: overLimit ? "#FCA5A5" : percent >= 80 ? "#FCD34D" : "#86EFAC",
                                }} />
                            </div>
                        )}
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: "12px" }}>
                        <Stat label={t("Asset limit")} value={unlimited ? t("Unlimited") : n(maxAssets)}
                              sub={offlinePilot ? t("pilot, while offline") : null} />
                        <Stat label={t("Add-on packs")} value={n(addonPacks || 0)}
                              sub={tx("{{assets}} assets each", { assets: ADDON.assets })} />
                        <Stat label={t("Expires")} value={fmtDate(expiresAt)} />
                        {offlineLicense
                            ? <Stat label={t("Offline license file valid until")} value={fmtDate(offlineUntil)} sub={t("no contact with the license server")} />
                            : <Stat label={t("Last contact with the license server")} value={fmtDate(lastContactAt, true)} />}
                    </div>
                </div>
            ) : (
                /* ---- no license ---- */
                <div style={{
                    background: "linear-gradient(135deg, #1f2937 0%, #374151 100%)", borderRadius: "20px",
                    padding: "36px 40px", marginBottom: "48px", color: "white", boxShadow: "0 20px 60px rgba(0,0,0,0.2)",
                }}>
                    <div style={{ display: "flex", alignItems: "flex-start", gap: "24px", flexWrap: "wrap" }}>
                        <div style={{ flex: 1, minWidth: "260px" }}>
                            <div style={{
                                display: "inline-flex", alignItems: "center", gap: "8px",
                                backgroundColor: "rgba(239,68,68,0.2)", border: "1px solid rgba(239,68,68,0.4)",
                                borderRadius: "30px", padding: "6px 16px", fontSize: "13px", color: "#FCA5A5", marginBottom: "20px",
                            }}>
                                <i className="fa-solid fa-lock" />
                                {t("No Active Licence")}
                            </div>
                            <div style={{ fontSize: "22px", fontWeight: 700, marginBottom: "8px" }}>{t("Activate Your Licence")}</div>
                            <div style={{ fontSize: "14px", opacity: 0.7, marginBottom: "24px", lineHeight: 1.6 }}>
                                {t("Enter your licence key below to unlock full access to all features.")}
                            </div>
                            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                                <input
                                    type="text"
                                    placeholder={t("XXXX-XXXX-XXXX-XXXX")}
                                    value={licenseKey}
                                    onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
                                    disabled={isActivating}
                                    maxLength={19}
                                    dir="ltr"
                                    style={{
                                        flex: 1, minWidth: "200px", padding: "12px 16px", borderRadius: "10px",
                                        border: "1px solid rgba(255,255,255,0.2)", backgroundColor: "rgba(255,255,255,0.08)",
                                        color: "white", fontSize: "15px", textAlign: "center", letterSpacing: "3px",
                                        fontFamily: "monospace", fontWeight: 600, outline: "none",
                                    }}
                                />
                                <button
                                    onClick={handleActivate}
                                    disabled={isActivating || !licenseKey.trim()}
                                    style={{
                                        padding: "12px 28px", borderRadius: "10px", border: "none",
                                        backgroundColor: isActivating || !licenseKey.trim() ? "rgba(255,255,255,0.1)" : "#3B82F6",
                                        color: "white", fontSize: "14px", fontWeight: 700, whiteSpace: "nowrap",
                                        cursor: isActivating || !licenseKey.trim() ? "not-allowed" : "pointer",
                                    }}
                                >
                                    {isActivating ? t("⏳ Activating...") : t("Activate")}
                                </button>
                            </div>
                            <div style={{ marginTop: "16px", fontSize: "12px", opacity: 0.5 }}>
                                {t("Don't have a key? Contact your system administrator.")}
                            </div>
                        </div>
                        <div style={{
                            backgroundColor: "rgba(255,255,255,0.07)", borderRadius: "14px", padding: "20px 24px",
                            border: "1px solid rgba(255,255,255,0.12)", minWidth: "220px",
                        }}>
                            <div style={{ fontSize: "13px", opacity: 0.6, marginBottom: "12px", fontWeight: 600 }}>
                                <i className="fa-solid fa-gift" /> {t("FREE PILOT PLAN")}
                            </div>
                            <div style={{ fontSize: "14px", lineHeight: 1.9 }}>
                                <div>{tx("{{count}} assets", { count: PILOT.assets })}</div>
                                <div>{t("1 month")}</div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {isValid && offlineLicense && (
                <div style={{ marginTop: "-28px", marginBottom: "40px" }}>
                    <OfflineActivation renewal />
                </div>
            )}
            {!isValid && !isValidating && (
                <div style={{ marginTop: "-28px", marginBottom: "40px" }}>
                    <OfflineActivation />
                </div>
            )}

            {/* ===== PLANS ===== */}
            <div style={{ marginBottom: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
                    <div style={{ width: "4px", height: "28px", backgroundColor: "#1e3a5f", borderRadius: "2px" }} />
                    <h2 style={{ margin: 0, fontSize: "20px", fontWeight: 700, color: "#111827" }}>{t("Available Licence Plans")}</h2>
                </div>
                <p style={{ margin: 0, fontSize: "14px", color: "#6B7280", paddingInlineStart: "16px", lineHeight: 1.7 }}>
                    {tx("Licensed by the number of managed assets. Every plan except the pilot and Unlimited can be extended with add-on packs of {{assets}} assets: an organisation with 600 assets takes the 500 plan with two add-ons.", { assets: ADDON.assets })}
                </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))", gap: "14px" }}>
                {PLANS.map((plan) => (
                    <LicenseCard key={plan.code} plan={plan} isActive={isValid && !offlinePilot && planCode === plan.code} />
                ))}
                <LicenseCard addon />
            </div>

            <div style={{
                marginTop: "40px", padding: "18px 20px", borderTop: "1px solid #E5E7EB",
                fontSize: "13px", color: "#6B7280", lineHeight: 1.8,
            }}>
                <i className="fa-solid fa-shield-halved" style={{ marginInlineEnd: "6px" }} />
                {tx("NGCorion checks its license with the license server every hour. Without contact for {{hours}} hours it runs as a pilot license ({{assets}} assets) for up to {{days}} days, then stops until it can reach the server; the plan returns at the first contact.", {
                    hours: OFFLINE_GRACE_HOURS, assets: PILOT.assets, days: PILOT.days,
                })}
            </div>
        </div>
    );
};
