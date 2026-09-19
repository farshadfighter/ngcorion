import React from "react";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";
import { usePermission } from "../hooks/usePermission";

import { AssetList } from "./AssetList/AssetList";
import AutoDiscovery from "./AutoDiscovery/AutoDiscovery";
import { HardeningMain } from "./Hardening/HardeningMain";

// ── Access denied (shown when a user lacks read permission for a section) ──────
export const AccessDenied = ({ menuName }) => (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60vh", gap: "16px", color: "#6B7280" }}>
        <div style={{ fontSize: "48px" }}><i className="fa-solid fa-lock" /></div>
        <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>Access Denied</h2>
        <p style={{ fontSize: "14px", margin: 0 }}>You don't have permission to view <strong>{menuName}</strong>.</p>
        <p style={{ fontSize: "13px", margin: 0, color: "#9CA3AF" }}>Contact your administrator to request access.</p>
    </div>
);

// ── Placeholder for sections that are not built yet ───────────────────────────
export const ComingSoon = ({ name }) => (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60vh", gap: "16px", color: "#6B7280" }}>
        <div style={{ fontSize: "48px" }}>🚧</div>
        <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>{name}</h2>
        <p style={{ fontSize: "14px", margin: 0 }}>This section is coming soon.</p>
    </div>
);

// ── Per-route permission guard ────────────────────────────────────────────────
// Renders `children` when the user can read `module`, otherwise AccessDenied.
export const RequirePermission = ({ module, name, children }) => {
    const allowed = usePermission(module, "read");
    return allowed ? children : <AccessDenied menuName={name} />;
};

// ── Per-route role guard ──────────────────────────────────────────────────────
// Deployment has no module permission of its own - it's gated by role
// (admin/manager) only, matching the backend's require_admin_or_manager.
export const RequireRole = ({ roles, name, children }) => {
    const { role } = useSelector((state) => state.auth);
    const allowed = roles.includes(role);
    return allowed ? children : <AccessDenied menuName={name} />;
};

// ── Overview home (the dashboard stat cards) ──────────────────────────────────
export const OverviewHome = () => (
    <div className="dashboard-cards">
        <div className="stat-card">
            <div className="card-icon"><img style={{ width: "55px" }} src="/icons/haedenIcon.svg" alt="" /></div>
            <div className="card-title">Total Assets</div>
            <div className="card-description">Number of all assets in the system</div>
        </div>
        <div className="stat-card">
            <div className="card-icon"><img src="/icons/iconcheck.svg" alt="" /></div>
            <div className="card-title">Active Assets</div>
            <div className="card-description">Assets currently active and operational</div>
        </div>
        <div className="stat-card">
            <div className="card-icon"><img src="/icons/icondenger.svg" alt="" /></div>
            <div className="card-title">Pending Issues</div>
            <div className="card-description">Issues awaiting resolution</div>
        </div>
        <div className="stat-card">
            <div className="card-icon"><img src="/icons/iconuser.svg" alt="" /></div>
            <div className="card-title">Total Users</div>
            <div className="card-description">Registered users in the system</div>
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
