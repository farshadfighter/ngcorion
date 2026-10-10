/**
 * Dialog for a refusal because of the license's asset limit: an asset that
 * could not be added, or an audit/hardening of an asset outside the license.
 * Opened by the api.js "asset-limit" event (a 403 with X-Asset-Limit).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { getLicenseUsageThunk } from "../../store/licenseSlice";
import { ADDON } from "./licenseConfig";
import { t } from "../../i18n";
import { tx } from "../../i18n/tx";

const AssetLimitModal = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { maxAssets, usage, offlinePilot } = useSelector((state) => state.license);
    const [open, setOpen] = useState(false);
    const closeRef = useRef(null);

    const close = useCallback(() => setOpen(false), []);

    useEffect(() => {
        const onLimit = () => {
            setOpen(true);
            dispatch(getLicenseUsageThunk());
        };
        window.addEventListener("asset-limit", onLimit);
        return () => window.removeEventListener("asset-limit", onLimit);
    }, [dispatch]);

    useEffect(() => {
        if (!open) return undefined;
        const onKey = (e) => e.key === "Escape" && close();
        document.addEventListener("keydown", onKey);
        setTimeout(() => closeRef.current?.focus(), 50);
        return () => document.removeEventListener("keydown", onKey);
    }, [open, close]);

    if (!open) return null;
    const used = usage?.used;
    const known = used !== undefined && used !== null && maxAssets !== null && maxAssets !== undefined;

    return (
        <div role="dialog" aria-modal="true" aria-labelledby="asset-limit-title" onClick={close} style={{
            position: "fixed", inset: 0, backgroundColor: "rgba(15,23,42,0.45)", zIndex: 1100,
            display: "flex", alignItems: "center", justifyContent: "center", padding: "16px",
        }}>
            <div onClick={(e) => e.stopPropagation()} style={{
                backgroundColor: "white", borderRadius: "14px", padding: "28px", maxWidth: "480px", width: "100%",
                boxShadow: "0 20px 50px rgba(0,0,0,0.25)",
            }}>
                <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "14px" }}>
                    <i className="fa-solid fa-server" style={{ fontSize: "22px", color: "#DC2626" }} />
                    <h2 id="asset-limit-title" style={{ margin: 0, fontSize: "18px", color: "#111827" }}>
                        {t("License asset limit")}
                    </h2>
                </div>
                <p style={{ fontSize: "14px", color: "#374151", lineHeight: 1.8, margin: "0 0 10px" }}>
                    {known
                        ? tx("The license covers {{limit}} assets and the inventory has {{used}}.", { limit: maxAssets, used })
                        : t("The license does not cover this asset.")}
                </p>
                <p style={{ fontSize: "14px", color: "#374151", lineHeight: 1.8, margin: 0 }}>
                    {offlinePilot
                        ? t("NGCorion is running as a pilot license because it cannot reach the license server; the full plan returns as soon as the connection does.")
                        : tx("New assets cannot be added beyond the limit, and audits and hardening run only on the first assets the license covers (the oldest). Remove assets you no longer need, or extend the license with add-on packs of {{assets}} assets.", { assets: ADDON.assets })}
                </p>
                <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end", marginTop: "24px", flexWrap: "wrap" }}>
                    <button ref={closeRef} onClick={close} style={{
                        padding: "9px 18px", borderRadius: "8px", border: "1px solid #D1D5DB",
                        backgroundColor: "white", cursor: "pointer", fontSize: "14px",
                    }}>
                        {t("Close")}
                    </button>
                    <button onClick={() => { close(); navigate("/settings/license"); }} style={{
                        padding: "9px 18px", borderRadius: "8px", border: "none", backgroundColor: "#1e3a5f",
                        color: "white", cursor: "pointer", fontSize: "14px", fontWeight: 600,
                    }}>
                        {t("Go to Licence")}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AssetLimitModal;
