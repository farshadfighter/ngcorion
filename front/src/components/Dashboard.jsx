import React from 'react';
import { useSelector, useDispatch } from "react-redux";
import { logout } from "../store/authSlice";
import { getLicenseStatusThunk } from "../store/licenseSlice";
import { useNavigate } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { UserManagement } from "./UserManagement/UserManagement";
import { AssetList } from "./AssetList/AssetList";
import { AssetRequirement } from "./AssetRequirement/AssetRequirement";
import AutoDiscovery from "./AutoDiscovery/AutoDiscovery";
import { AuditingList } from "./Auditing/AuditingList";
import { HardeningMain } from "./Hardening/HardeningMain";
import { License } from "./License/License";
import LicenseBadge from './License/LicenseBadge';
import { ChangePasswordModal } from "./ChangePasswordModal";
import { usePermission } from "../hooks/usePermission";
import { LogsPage } from "./Logs/LogsPage";
import BackupPage from "./Backup/BackupPage";
import { AssetManagementDashboard } from "./AssetManagement/AssetManagementDashboard";
import { AuditingDashboard } from "./Auditing/AuditingDashboard";

import "../assets/Dashboard.css";

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

    // ── Permissions ───────────────────────────────────────────────────────────
    const canReadAssetReq  = usePermission("asset_requirement",    "read");
    const canReadAssetList = usePermission("asset_list",           "read");
    const canReadAutoDisc  = usePermission("asset_auto_discovery", "read");
    const canReadAuditing  = usePermission("auditing",             "read");
    const canReadHardening = usePermission("hardening",            "read");
    const canReadUserMgmt  = usePermission("user_management",      "read");
    const canReadLogs      = usePermission("logs",                 "read");
    const canReadBackup    = usePermission("backup",               "read");

    useEffect(() => {
        const timer = setInterval(() => setCurrentTime(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        const handleClickOutside = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
                setShowDropdown(false);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    useEffect(() => {
        dispatch(getLicenseStatusThunk());
    }, [dispatch]);

    const currentDate = currentTime.toLocaleDateString("en-US", {
        weekday: "long", year: "numeric", month: "long", day: "numeric",
    });
    const currentTimeString = currentTime.toLocaleTimeString("en-US", {
        hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
    });

    const menuToModule = {
        "hardening":        "hardening",
        "operation-device": "auditing",
        "auto-discovery":   "auto_discovery",
        "asset-list":       "asset",
    };
    const currentModule = menuToModule[activeMenu] || "";

    const handleLogout = () => {
        dispatch(logout());
        navigate("/");
    };

    const handleNavigateToLicence = () => setActiveMenu("licence");
    const handleNavigateToAuditing = () => setActiveMenu("operation-device");

    const pageTitles = {
        "dashboard":           "Dashboard",
        "asset-management":    "Asset Management",
        "asset-requirement":   "Asset Requirement",
        "asset-list":          "Asset List",
        "auto-discovery":      "Auto Discovery",
        "auditing":            "Auditing",
        "operation-device":    "Operation and Device",
        "hardening":           "Hardening",
        "hardening-operation": "Operation and Device",
        "risk-intelligence":   "Risk Intelligence",
        "risk-exposure":       "Risk & Exposure",
        "attack-surface":      "Attack Surface",
        "backup":              "Configuration Backup",
        "user-management":     "User Management",
        "system-logs":         "System Logs",
        "ntp-configuration":   "NTP Configuration",
        "snmp-configuration":  "SNMP Configuration",
        "licence":             "License Management",
    };

    const AccessDenied = ({ menuName }) => (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60vh", gap: "16px", color: "#6B7280" }}>
            <div style={{ fontSize: "48px" }}>🔒</div>
            <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>Access Denied</h2>
            <p style={{ fontSize: "14px", margin: 0 }}>You don't have permission to view <strong>{menuName}</strong>.</p>
            <p style={{ fontSize: "13px", margin: 0, color: "#9CA3AF" }}>Contact your administrator to request access.</p>
        </div>
    );

    const ComingSoon = ({ name }) => (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60vh", gap: "16px", color: "#6B7280" }}>
            <div style={{ fontSize: "48px" }}>🚧</div>
            <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>{name}</h2>
            <p style={{ fontSize: "14px", margin: 0 }}>This section is coming soon.</p>
        </div>
    );

    const renderContent = () => {
        switch (activeMenu) {
            case "asset-management":
                return <AssetManagementDashboard />;

            case "dashboard":
                return (
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

            case "asset-requirement":
                return canReadAssetReq ? <AssetRequirement /> : <AccessDenied menuName="Asset Requirement" />;

            case "asset-list":
                return canReadAssetList ? <AssetList onNavigateToLicence={handleNavigateToLicence} /> : <AccessDenied menuName="Asset List" />;

            case "auto-discovery":
                return canReadAutoDisc ? <AutoDiscovery onNavigateToLicence={handleNavigateToLicence} /> : <AccessDenied menuName="Auto Discovery" />;

            case "auditing":
                return canReadAuditing ? <AuditingDashboard /> : <AccessDenied menuName="Auditing" />;

            case "operation-device":
                return canReadAuditing ? <AuditingList onNavigateToLicence={handleNavigateToLicence} /> : <AccessDenied menuName="Auditing" />;

            case "hardening":
            case "hardening-operation":
                return canReadHardening
                    ? <HardeningMain onNavigateToAuditing={handleNavigateToAuditing} onNavigateToLicence={handleNavigateToLicence} />
                    : <AccessDenied menuName="Hardening" />;

            case "risk-intelligence":
            case "risk-exposure":
                return <ComingSoon name="Risk & Exposure" />;

            case "attack-surface":
                return <ComingSoon name="Attack Surface" />;

            case "backup":
                return canReadBackup ? <BackupPage /> : <AccessDenied menuName="Configuration Backup" />;

            case "user-management":
                return canReadUserMgmt ? <UserManagement /> : <AccessDenied menuName="User Management" />;

            case "system-logs":
                return canReadLogs ? <LogsPage /> : <AccessDenied menuName="System Logs" />;

            case "ntp-configuration":
                return <ComingSoon name="NTP Configuration" />;

            case "snmp-configuration":
                return <ComingSoon name="SNMP Configuration" />;

            case "licence":
                return <License />;

            default:
                return null;
        }
    };

    return (
        <div className="dashboard-container">
            {/* ── SIDEBAR ── */}
            <aside className={`sidebar ${isSidebarCollapsed ? "collapsed" : ""}`}>
                <div className="sidebar-header">
                    {!isSidebarCollapsed && <img src="/logowhite.png" alt="logo" className="sidebar-logo" />}
                    {isSidebarCollapsed  && <img src="/logowhite.png" alt="logo" className="sidebar-logo-small" />}
                    <button className="toggle-sidebar-btn" onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}>
                        {isSidebarCollapsed ? "›" : "‹"}
                    </button>
                </div>

                <nav className="sidebar-nav">

                    {/* ── Dashboard ── */}
                    <div className={`nav-item ${activeMenu === "dashboard" ? "active" : ""}`}
                         onClick={() => setActiveMenu("dashboard")} title="Dashboard">
                        <img src="/icons/dashboard.svg" alt="" className="nav-icon-img" />
                        {!isSidebarCollapsed && <span>Dashboard</span>}
                    </div>

                    {/* ── ASSET MANAGEMENT ── */}
                    {(canReadAssetReq || canReadAssetList || canReadAutoDisc) && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "asset-management" ? "nav-section-active" : ""}`}
                                     onClick={() => setActiveMenu("asset-management")}>
                                    <img src="/icons/asset-management.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Asset Management</span>
                                </div>
                            )}
                            {canReadAssetReq && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-requirement" ? "active" : ""}`}
                                     onClick={() => setActiveMenu("asset-requirement")} title="Asset Requirement">
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Asset Requirement</span>}
                                </div>
                            )}
                            {canReadAssetList && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-list" ? "active" : ""}`}
                                     onClick={() => setActiveMenu("asset-list")} title="Asset List">
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Asset List</span>}
                                </div>
                            )}
                            {canReadAutoDisc && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "auto-discovery" ? "active" : ""}`}
                                     onClick={() => setActiveMenu("auto-discovery")} title="Auto Discovery">
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Auto Discovery</span>}
                                </div>
                            )}
                        </>
                    )}

                    {/* ── AUDITING ── */}
                    {canReadAuditing && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "auditing" ? "nav-section-active" : ""}`}
                                     onClick={() => setActiveMenu("auditing")}>
                                    <img src="/icons/auditing.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Auditing</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "operation-device" ? "active" : ""}`}
                                 onClick={() => setActiveMenu("operation-device")} title="Operation & Device">
                                {isSidebarCollapsed && <img src="/icons/auditing.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>Operation & Device</span>}
                            </div>
                        </>
                    )}

                    {/* ── HARDENING ── */}
                    {canReadHardening && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className="nav-section">
                                    <img src="/icons/hardening.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Hardening</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "hardening" || activeMenu === "hardening-operation" ? "active" : ""}`}
                                 onClick={() => setActiveMenu("hardening")} title="Operation and Device">
                                {isSidebarCollapsed && <img src="/icons/hardening.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>Operation & Device</span>}
                            </div>
                        </>
                    )}

                    {/* ── RISK INTELLIGENCE ── */}
                    {!isSidebarCollapsed && (
                        <div className="nav-section">
                            <img src="/icons/asset-management.svg" alt="" className="section-icon" style={{ opacity: 0.4 }} />
                            <span className="nav-section-title" style={{ opacity: 0.4 }}>Risk Intelligence</span>
                        </div>
                    )}
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "risk-exposure" ? "active" : ""} nav-item-disabled`}
                         onClick={() => setActiveMenu("risk-exposure")} title="Risk & Exposure">
                        {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" style={{ opacity: 0.4 }} />}
                        {!isSidebarCollapsed && <span style={{ opacity: 0.5 }}>Risk & Exposure</span>}
                    </div>
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "attack-surface" ? "active" : ""} nav-item-disabled`}
                         onClick={() => setActiveMenu("attack-surface")} title="Attack Surface">
                        {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" style={{ opacity: 0.4 }} />}
                        {!isSidebarCollapsed && <span style={{ opacity: 0.5 }}>Attack Surface</span>}
                    </div>

                    {/* ── CONFIGURATION BACKUP ── */}
                    {canReadBackup && (
                        <div className={`nav-item ${activeMenu === "backup" ? "active" : ""}`}
                             onClick={() => setActiveMenu("backup")} title="Configuration Backup">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                                 className="nav-icon-img" style={{ flexShrink: 0 }}>
                                <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
                                <polyline points="17 21 17 13 7 13 7 21" />
                                <polyline points="7 3 7 8 15 8" />
                            </svg>
                            {!isSidebarCollapsed && <span>Configuration Backup</span>}
                        </div>
                    )}

                    {/* ── SYSTEM SETTINGS ── */}
                    {!isSidebarCollapsed && (canReadUserMgmt || canReadLogs) && (
                        <div className="nav-section">
                            <img src="/icons/administration.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">System Settings</span>
                        </div>
                    )}
                    {canReadUserMgmt && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "user-management" ? "active" : ""}`}
                             onClick={() => setActiveMenu("user-management")} title="User Management">
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>User Management</span>}
                        </div>
                    )}
                    {canReadLogs && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "system-logs" ? "active" : ""}`}
                             onClick={() => setActiveMenu("system-logs")} title="System Logs">
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>System Logs</span>}
                        </div>
                    )}
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "ntp-configuration" ? "active" : ""} nav-item-disabled`}
                         onClick={() => setActiveMenu("ntp-configuration")} title="NTP Configuration">
                        {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" style={{ opacity: 0.4 }} />}
                        {!isSidebarCollapsed && <span style={{ opacity: 0.5 }}>NTP Configuration</span>}
                    </div>
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "snmp-configuration" ? "active" : ""} nav-item-disabled`}
                         onClick={() => setActiveMenu("snmp-configuration")} title="SNMP Configuration">
                        {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" style={{ opacity: 0.4 }} />}
                        {!isSidebarCollapsed && <span style={{ opacity: 0.5 }}>SNMP Configuration</span>}
                    </div>
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "licence" ? "active" : ""}`}
                         onClick={() => setActiveMenu("licence")} title="License Management">
                        <img src="/icons/license.svg" alt="" className="nav-icon-img nav-icon-license" />
                        {!isSidebarCollapsed && <span>License Management</span>}
                    </div>

                </nav>

                {/* ── FOOTER ── */}
                <div className="sidebar-footer">
                    {!isSidebarCollapsed && (
                        <>
                            <div className="user-info">
                                <div className="user-avatar">{username?.charAt(0).toUpperCase()}</div>
                                <div className="user-details">
                                    <div className="user-name">{username}</div>
                                    <div className="user-role">{role}</div>
                                </div>
                            </div>
                            <div style={{ position: "relative" }} ref={dropdownRef}>
                                <button className="logout-btn" onClick={() => setShowDropdown(!showDropdown)}>⋮</button>
                                {showDropdown && (
                                    <div className="user-menu-dropdown-container">
                                        <button className="user-menu-dropdown-btn action-primary"
                                                onClick={() => { setShowChangePassword(true); setShowDropdown(false); }}>
                                            <i className="fa-solid fa-key"></i> Change Password
                                        </button>
                                        <button className="user-menu-dropdown-btn action-danger" onClick={handleLogout}>
                                            <i className="fa-solid fa-right-from-bracket"></i> Logout
                                        </button>
                                    </div>
                                )}
                            </div>
                        </>
                    )}
                    {isSidebarCollapsed && (
                        <div className="user-avatar-collapsed" onClick={handleLogout}>
                            {username?.charAt(0).toUpperCase()}
                        </div>
                    )}
                </div>
            </aside>

            {/* ── MAIN CONTENT ── */}
            <main className="main-content">
                <header className="dashboard-header">
                    <h1 className="page-title">
                        {pageTitles[activeMenu] || "Dashboard"}
                    </h1>
                    <div className="header-center" style={{ flex: 1, display: "flex", justifyContent: "center" }}>
                        {currentModule && <LicenseBadge module={currentModule} />}
                    </div>
                    <div className="header-right">
                        <div className="date-time">
                            <div className="current-date">{currentDate}</div>
                            <div className="current-time" style={{ paddingLeft: "25px" }}>
                                <img src="/icons/watch.png" style={{ width: "15px", height: "15px", margin: "15px 8px -1px 1px" }} alt="clock" />
                                {currentTimeString}
                            </div>
                        </div>
                    </div>
                </header>

                {renderContent()}
            </main>

            {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}
        </div>
    );
};