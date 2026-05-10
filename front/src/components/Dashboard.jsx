import React from 'react';
import { useSelector, useDispatch } from "react-redux";
import { logout } from "../store/authSlice";
import { useNavigate } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { UserManagement } from "./UserManagement/UserManagement";
import { AssetList } from "./AssetList/AssetList";
import { AssetRequirement } from "./AssetRequirement/AssetRequirement";
import AutoDiscovery from "./AutoDiscovery/AutoDiscovery";
import { AuditingList } from "./Auditing/AuditingList";
import { HardeningMain } from "./Hardening/HardeningMain";
import { License } from "./License/License";
import  LicenseBadge  from './License/LicenseBadge';
import { ChangePasswordModal } from "./ChangePasswordModal";
import { usePermission } from "../hooks/usePermission";

// ==========================================
// کامپوننت نمایش خطای دسترسی
// ==========================================

const AccessDenied = ({ menuName }) => (
    <div style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "60vh",
        gap: "16px",
        color: "#6B7280",
    }}>
        <div style={{ fontSize: "48px" }}>🔒</div>
        <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>
            Access Denied
        </h2>
        <p style={{ fontSize: "14px", margin: 0 }}>
            You don't have permission to view <strong>{menuName}</strong>.
        </p>
        <p style={{ fontSize: "13px", margin: 0, color: "#9CA3AF" }}>
            Contact your administrator to request access.
        </p>
    </div>
);


// ==========================================
// کامپوننت اصلی Dashboard
// ==========================================

export const Dashboard = () => {
    const { username, role } = useSelector((state) => state.auth);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [activeMenu, setActiveMenu] = useState("dashboard");
    const [currentTime, setCurrentTime] = useState(new Date());
    const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
    const [showDropdown, setShowDropdown] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const dropdownRef = useRef(null);

    // ==========================================
    // Permission Checks
    // ==========================================
    const canReadAssetReq   = usePermission("asset_requirement",    "read");
    const canReadAssetList  = usePermission("asset_list",           "read");
    const canReadAutoDisc   = usePermission("asset_auto_discovery", "read");
    const canReadAuditing   = usePermission("auditing",             "read");
    const canReadHardening  = usePermission("hardening",            "read");
    const canReadUserMgmt   = usePermission("user_management",      "read");
    const canReadLogs       = usePermission("logs",                 "read");

    // ==========================================
    // Handlers
    // ==========================================
    useEffect(() => {
        const handleClickOutside = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
                setShowDropdown(false);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);
    const handleLogout = () => {
        dispatch(logout());
        navigate("/");
    };

    const handleNavigateToAuditing = () => {
        setActiveMenu("operation-device");
    };

    const handleNavigateToLicence = () => {
        setActiveMenu("licence");
    };

    useEffect(() => {
        const timer = setInterval(() => {
            setCurrentTime(new Date());
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    const currentDate = currentTime.toLocaleDateString("en-US", {
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric",
    });
    const currentTimeString = currentTime.toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
// ✅ اضافه کن
    const menuToModule = {
        "hardening":        "hardening",
        "operation-device": "auditing",
        "auto-discovery":   "auto_discovery",
        "asset-list":       "asset",
    };
    const currentModule = menuToModule[activeMenu] || "";

    // ==========================================
    // Helper — رندر محتوای هر منو با چک دسترسی
    // ==========================================

    const renderContent = () => {
        switch (activeMenu) {

            case "dashboard":
                return (
                    <div className="dashboard-cards">
                        <div className="stat-card">
                            <div className="card-icon" ><img style={{width:"55px"}} src="/icons/haedenIcon.svg"/></div>
                            <div className="card-title">Total Assets</div>
                            <div className="card-description">Number of all assets in the system</div>
                        </div>
                        <div className="stat-card">
                            <div className="card-icon"><img src="/icons/iconcheck.svg"/></div>
                            <div className="card-title">Active Assets</div>
                            <div className="card-description">Assets currently active and operational</div>
                        </div>
                        <div className="stat-card">
                            <div className="card-icon"><img src="/icons/icondenger.svg"/></div>
                            <div className="card-title">Pending Issues</div>
                            <div className="card-description">Issues awaiting resolution</div>
                        </div>
                        <div className="stat-card">
                            <div className="card-icon"><img src="/icons/iconuser.svg"/></div>
                            <div className="card-title">Total Users</div>
                            <div className="card-description">Registered users in the system</div>
                        </div>
                    </div>
                );

            case "user-management":
                return canReadUserMgmt
                    ? <UserManagement />
                    : <AccessDenied menuName="User Management" />;

            case "asset-requirement":
                return canReadAssetReq
                    ? <AssetRequirement />
                    : <AccessDenied menuName="Asset Requirement" />;

            case "asset-list":
                return canReadAssetList
                    ? <AssetList onNavigateToLicence={handleNavigateToLicence} />
                    : <AccessDenied menuName="Asset List" />;

            case "auto-discovery":
                return canReadAutoDisc
                    ? <AutoDiscovery onNavigateToLicence={handleNavigateToLicence} />
                    : <AccessDenied menuName="Auto Discovery" />;

            case "operation-device":
                return canReadAuditing
                    ? <AuditingList onNavigateToLicence={handleNavigateToLicence} />
                    : <AccessDenied menuName="Auditing" />;

            case "hardening":
                return canReadHardening
                    ? <HardeningMain
                        onNavigateToAuditing={handleNavigateToAuditing}
                        onNavigateToLicence={handleNavigateToLicence}
                    />
                    : <AccessDenied menuName="Hardening" />;

            case "logs":
                return canReadLogs
                    ? (
                        <div className="placeholder-content">
                            <h3>Logs</h3>
                            <p>Coming soon...</p>
                        </div>
                    )
                    : <AccessDenied menuName="Logs" />;

            case "licence":
                return <License />;

            default:
                return null;
        }
    };

    // ==========================================
    // Render
    // ==========================================

    return (
        <div className="dashboard-container">
            {/* SIDEBAR */}
            <aside className={`sidebar ${isSidebarCollapsed ? "collapsed" : ""}`}>
                <div className="sidebar-header">
                    {!isSidebarCollapsed && (
                        <img src="/logowhite.png" alt="logo" className="sidebar-logo" />
                    )}
                    {isSidebarCollapsed && (
                        <img src="/logowhite.png" alt="logo" className="sidebar-logo-small" />
                    )}
                    <button
                        className="toggle-sidebar-btn"
                        onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
                    >
                        {isSidebarCollapsed ? "›" : "‹"}
                    </button>
                </div>

                <nav className="sidebar-nav">
                    {/* Dashboard - همه دسترسی دارن */}
                    <div
                        className={`nav-item ${activeMenu === "dashboard" ? "active" : ""}`}
                        onClick={() => setActiveMenu("dashboard")}
                        title="Dashboard"
                    >
                        <img src="/icons/dashboard.svg" alt="" className="nav-icon-img" />
                        {!isSidebarCollapsed && <span>dashboard</span>}
                    </div>

                    {/* ASSET MANAGEMENT Section */}
                    {!isSidebarCollapsed && (canReadAssetReq || canReadAssetList || canReadAutoDisc) && (
                        <div className="nav-section">
                            <img src="/icons/asset-management.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">ASSET MANAGEMENT</span>
                        </div>
                    )}

                    {canReadAssetReq && (
                        <div
                            className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-requirement" ? "active" : ""}`}
                            onClick={() => setActiveMenu("asset-requirement")}
                            title="Asset Requirement"
                        >
                            {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>Asset Requirement</span>}
                        </div>
                    )}

                    {canReadAssetList && (
                        <div
                            className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-list" ? "active" : ""}`}
                            onClick={() => setActiveMenu("asset-list")}
                            title="Asset List"
                        >
                            {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>Asset List</span>}
                        </div>
                    )}

                    {canReadAutoDisc && (
                        <div
                            className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "auto-discovery" ? "active" : ""}`}
                            onClick={() => setActiveMenu("auto-discovery")}
                            title="Auto Discovery"
                        >
                            {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>Auto Discovery</span>}
                        </div>
                    )}

                    {/* Auditing Section */}
                    {canReadAuditing && !isSidebarCollapsed && (
                        <div className="nav-section">
                            <img src="/icons/auditing.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">Auditing</span>
                        </div>
                    )}

                    {canReadAuditing && (
                        <div
                            className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "operation-device" ? "active" : ""}`}
                            onClick={() => setActiveMenu("operation-device")}
                            title="Operation and Device"
                        >
                            {isSidebarCollapsed && <img src="/icons/auditing.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>Operation and Device</span>}
                        </div>
                    )}

                    {/* Hardening */}
                    {canReadHardening && (
                        <div
                            className={`nav-item ${activeMenu === "hardening" ? "active" : ""}`}
                            onClick={() => setActiveMenu("hardening")}
                            title="Hardening"
                        >
                            <img src="/icons/hardening.svg" alt="" className="nav-icon-img" />
                            {!isSidebarCollapsed && <span>Hardening</span>}
                        </div>
                    )}

                    {/* ADMINISTRATION Section */}
                    {!isSidebarCollapsed && (canReadUserMgmt || canReadLogs) && (
                        <div className="nav-section">
                            <img src="/icons/administration.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">Administration</span>
                        </div>
                    )}

                    {canReadUserMgmt && (
                        <div
                            className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "user-management" ? "active" : ""}`}
                            onClick={() => setActiveMenu("user-management")}
                            title="User Management"
                        >
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>User Management</span>}
                        </div>
                    )}

                    {canReadLogs && (
                        <div
                            className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "logs" ? "active" : ""}`}
                            onClick={() => setActiveMenu("logs")}
                            title="Logs"
                        >
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>Logs</span>}
                        </div>
                    )}

                    {/* Licence - همه دسترسی دارن */}
                    <div
                        className={`nav-item ${activeMenu === "licence" ? "active" : ""}`}
                        onClick={() => setActiveMenu("licence")}
                        title="Licence"
                    >
                        <img src="/icons/administration.svg" alt="" className="nav-icon-img" />
                        {!isSidebarCollapsed && <span>Licence</span>}
                    </div>
                </nav>

                <div className="sidebar-footer">
                    {!isSidebarCollapsed && (
                        <>
                            <div className="user-info">
                                <div className="user-avatar">
                                    {username?.charAt(0).toUpperCase()}
                                </div>
                                <div className="user-details">
                                    <div className="user-name">{username}</div>
                                    <div className="user-role">{role}</div>
                                </div>
                            </div>
                            <dgiv style={{ position: "relative" }} ref={dropdownRef}>
                                <button className="logout-btn" onClick={() => setShowDropdown(!showDropdown)}>
                                    ⋮
                                </button>
                                {showDropdown && (
                                    <div>
                                        <div
                                            onClick={() => { setShowChangePassword(true); setShowDropdown(false); }}
                                        >
                                            <i className="fa-solid fa-key"></i> Change Password
                                        </div>
                                        <div
                                            onClick={handleLogout}
                                        >
                                            <i className="fa-solid fa-right-from-bracket"></i> Logout
                                        </div>
                                    </div>
                                )}
                            </dgiv>
                        </>
                    )}
                    {isSidebarCollapsed && (
                        <div className="user-avatar-collapsed" onClick={handleLogout}>
                            {username?.charAt(0).toUpperCase()}
                        </div>
                    )}
                </div>
            </aside>

            {/* MAIN CONTENT */}
            <main className="main-content">
                <header className="dashboard-header">
                    <h1 className="page-title">
                        {activeMenu === "dashboard"        && "Dashboard"}
                        {activeMenu === "user-management"  && "User Management"}
                        {activeMenu === "asset-requirement"&& "Asset Requirement"}
                        {activeMenu === "asset-list"       && "Asset List"}
                        {activeMenu === "auto-discovery"   && "Auto Discovery"}
                        {activeMenu === "operation-device" && "Operation and Device"}
                        {activeMenu === "hardening"        && "Hardening"}
                        {activeMenu === "logs"             && "Logs"}
                        {activeMenu === "licence"          && "Licence"}
                    </h1>
                    {/* کانتینر جدید برای وسط هدر */}
                    <div className="header-center" style={{ flex: 1, display: 'flex', justifyContent: 'center' }}>
                        {currentModule && <LicenseBadge module={currentModule} />}
                    </div>

                    <div className="header-right">
                        <div className="date-time">
                            <div className="current-date">{currentDate}</div>
                            <div className="current-time">
                                <img
                                    src={"/icons/watch.png"}
                                    style={{ width: "15px", height: "15px", margin: "15px 8px -1px 1px" }}
                                    alt="clock"
                                />
                                {currentTimeString}
                            </div>
                        </div>
                    </div>


                </header>

                {renderContent()}
            </main>
            {showChangePassword && (
                <ChangePasswordModal onClose={() => setShowChangePassword(false)} />
            )}
        </div>
    );
};