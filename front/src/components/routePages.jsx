import React, { lazy } from "react";
import { useNavigate } from "react-router-dom";
import { usePermission } from "../hooks/usePermission";
import { t } from "../i18n";
import { tx } from "../i18n/tx";

const AssetList = lazy(() => import("./AssetList/AssetList").then((m) => ({ default: m.AssetList })));
const AutoDiscovery = lazy(() => import("./AutoDiscovery/AutoDiscovery"));
const HardeningMain = lazy(() => import("./Hardening/HardeningMain").then((m) => ({ default: m.HardeningMain })));

// ── Access denied (shown when a user lacks read permission for a section) ──────
export const AccessDenied = ({ menuName }) => (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60vh", gap: "16px", color: "#6B7280" }}>
        <div style={{ fontSize: "48px" }}><i className="fa-solid fa-lock" /></div>
        <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>{t("Access Denied")}</h2>
        <p style={{ fontSize: "14px", margin: 0 }}>{tx("You don't have permission to view {{page}}.", { page: <strong>{menuName}</strong> })}</p>
        <p style={{ fontSize: "13px", margin: 0, color: "#9CA3AF" }}>{t("Contact your administrator to request access.")}</p>
    </div>
);

// ── Placeholder for sections that are not built yet ───────────────────────────
export const ComingSoon = ({ name }) => (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60vh", gap: "16px", color: "#6B7280" }}>
        <div style={{ fontSize: "48px" }}>🚧</div>
        <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>{name}</h2>
        <p style={{ fontSize: "14px", margin: 0 }}>{t("This section is coming soon.")}</p>
    </div>
);

// ── Per-route permission guard ────────────────────────────────────────────────
// Renders `children` when the user can read `module`, otherwise AccessDenied.
export const RequirePermission = ({ module, name, children }) => {
    const allowed = usePermission(module, "read");
    return allowed ? children : <AccessDenied menuName={t(name)} />;
};

// ── Overview home (the dashboard stat cards) ──────────────────────────────────
export const OverviewHome = () => (
    <div className="dashboard-cards">
        <div className="stat-card">
            <div className="card-icon"><img style={{ width: "55px" }} src="/icons/haedenIcon.svg" alt="" /></div>
            <div className="card-title">{t("Total Assets")}</div>
            <div className="card-description">{t("Number of all assets in the system")}</div>
        </div>
        <div className="stat-card">
            <div className="card-icon"><img src="/icons/iconcheck.svg" alt="" /></div>
            <div className="card-title">{t("Active Assets")}</div>
            <div className="card-description">{t("Assets currently active and operational")}</div>
        </div>
        <div className="stat-card">
            <div className="card-icon"><img src="/icons/icondenger.svg" alt="" /></div>
            <div className="card-title">{t("Pending Issues")}</div>
            <div className="card-description">{t("Issues awaiting resolution")}</div>
        </div>
        <div className="stat-card">
            <div className="card-icon"><img src="/icons/iconuser.svg" alt="" /></div>
            <div className="card-title">{t("Total Users")}</div>
            <div className="card-description">{t("Registered users in the system")}</div>
        </div>
    </div>
);

// ── Thin route wrappers that translate the old onNavigate* callbacks into ──────
//    router navigation, so the child components stay unchanged.
export const AssetListRoute = () => {
    return <AssetList />;
};

export const AutoDiscoveryRoute = () => {
    return <AutoDiscovery />;
};

export const HardeningRoute = () => {
    const navigate = useNavigate();
    return (
        <HardeningMain
            onNavigateToAuditing={() => navigate("/audit/sessions")}
            onNavigateToLicence={() => navigate("/settings/license")}
        />
    );
};
