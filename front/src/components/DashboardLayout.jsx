import React from 'react';
import { useSelector, useDispatch } from "react-redux";
import { logout } from "../store/authSlice";
import { getLicenseStatusThunk } from "../store/licenseSlice";
import { useNavigate, useLocation, Outlet } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import LicenseBadge from './License/LicenseBadge';
import { ChangePasswordModal } from "./ChangePasswordModal";
import { usePermission } from "../hooks/usePermission";

import "../assets/Dashboard.css";

// Map the current URL path to a stable menu key. That key drives the sidebar
// active state, the header title and the license badge — reusing the same keys
// the sidebar used back when this was state-based view switching.
const menuFromPath = (pathname) => {
    if (pathname.startsWith("/assets/requirements")) return "asset-requirement";
    if (pathname.startsWith("/assets/inventory"))    return "asset-list";
    if (pathname.startsWith("/assets/discovery"))     return "auto-discovery";
    if (pathname.startsWith("/assets"))               return "asset-management";
    if (pathname.startsWith("/audit/sessions"))       return "operation-device";
    if (pathname.startsWith("/audit"))                return "auditing";
    // More specific first: /hardening/overview must not fall through to the
    // Operation & Device sub-item.
    if (pathname.startsWith("/hardening/overview"))   return "hardening-overview";
    if (pathname.startsWith("/hardening"))            return "hardening";
    if (pathname.startsWith("/backup"))               return "backup";
    if (pathname.startsWith("/topology"))             return "topology";
    if (pathname.startsWith("/architecture-validation")) return "architecture-validation";
    if (pathname.startsWith("/design-configuration/jobs")) return "design-configuration-jobs";
    if (pathname.startsWith("/design-configuration"))    return "design-configuration";
    if (pathname.startsWith("/deployment"))           return "deployment";
    if (pathname.startsWith("/drift"))                return "drift";
    if (pathname.startsWith("/settings/users"))       return "user-management";
    if (pathname.startsWith("/settings/logs"))        return "system-logs";
    if (pathname.startsWith("/settings/license"))     return "licence";
    if (pathname.startsWith("/settings/system"))      return "system-configuration";
    if (pathname.startsWith("/risk/assets"))          return "risk-asset";
    if (pathname.startsWith("/risk/exposure"))        return "risk-asset";
    if (pathname.startsWith("/risk/overview"))        return "risk-intelligence";
    return "dashboard";
};

export const DashboardLayout = () => {
    const { username, role } = useSelector((state) => state.auth);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { pathname } = useLocation();
    const activeMenu = menuFromPath(pathname);

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
    const canReadSysConfig = usePermission("system_config",        "read");
    const canReadTopology  = usePermission("topology",             "read");
    const canReadArchValidation = usePermission("architecture_validation", "read");
    const canReadDesignConfig = usePermission("design_configuration", "read");
    const canReadDeployment = role === "admin" || role === "manager";
    const canReadDrift     = usePermission("drift",                 "read");

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

    // Asset Management (asset-list, auto-discovery) is not license-gated, so
    // those pages don't show a license usage badge.
    const menuToModule = {
        "hardening":        "hardening",
        "operation-device": "auditing",
    };
    const currentModule = menuToModule[activeMenu] || "";

    const handleLogout = () => {
        dispatch(logout());
        navigate("/");
    };

    const pageTitles = {
        "dashboard":           "Dashboard",
        "asset-management":    "Asset Management",
        "asset-requirement":   "Asset Requirement",
        "asset-list":          "Asset List",
        "auto-discovery":      "Auto Discovery",
        "auditing":            "Auditing",
        "operation-device":    "Operation and Device",
        "hardening":           "Hardening",
        "hardening-overview":  "Hardening",
        "hardening-operation": "Operation and Device",
        "risk-intelligence":   "Risk Intelligence",
        "risk-asset":          "Risk Asset",
        "backup":              "Configuration Backup",
        "topology":            "Topology",
        "architecture-validation": "Architecture Validation",
        "design-configuration": "Design & Configuration",
        "design-configuration-jobs": "Configuration Jobs",
        "deployment":          "Deployment",
        "drift":               "Configuration Drift",
        "user-management":     "User Management",
        "system-logs":         "System Logs",
        "system-configuration": "System Configuration",
        "licence":             "License Management",
    };

    // One-line explanation shown under the page title. Filled in for the
    // network-design pipeline pages (Topology -> Design -> Configuration
    // Jobs -> Deployment -> Drift), whose purpose and relationship to each
    // other was not obvious from the UI alone.
    const pageSubtitles = {
        "topology": "The network as it actually is right now - every real asset and the cabling between them.",
        "architecture-validation": "Automated checks against the current topology (redundancy, exposure, best practice) - not part of the design pipeline below.",
        "design-configuration": "Step 1 of 4 - draw a planned blueprint here, even for devices that don't exist yet. Versioned; publish when ready to generate configuration.",
        "design-configuration-jobs": "Step 2 of 4 - turns a Design version into real device CLI commands, one per component mapped to an asset.",
        "deployment": "Step 3 of 4 - safely pushes a generated configuration to the real device: precheck, backup, apply, verify, and roll back on failure.",
        "drift": "Step 4 of 4 - compares a device's live configuration against its last backup to catch changes made outside this pipeline.",
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
                         onClick={() => navigate("/overview")} title="Dashboard">
                        <img src="/icons/dashboard.svg" alt="" className="nav-icon-img" />
                        {!isSidebarCollapsed && <span>Dashboard</span>}
                    </div>

                    {/* ── ASSET MANAGEMENT ── */}
                    {(canReadAssetReq || canReadAssetList || canReadAutoDisc) && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "asset-management" ? "nav-section-active" : ""}`}
                                     onClick={() => navigate("/assets")}>
                                    <img src="/icons/asset-management.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Asset Management</span>
                                </div>
                            )}
                            {canReadAssetReq && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-requirement" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/requirements")} title="Asset Requirement">
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Asset Requirement</span>}
                                </div>
                            )}
                            {canReadAssetList && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-list" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/inventory")} title="Asset List">
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Asset List</span>}
                                </div>
                            )}
                            {canReadAutoDisc && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "auto-discovery" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/discovery")} title="Auto Discovery">
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
                                     onClick={() => navigate("/audit")}>
                                    <img src="/icons/auditing.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Auditing</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "operation-device" ? "active" : ""}`}
                                 onClick={() => navigate("/audit/sessions")} title="Operation & Device">
                                {isSidebarCollapsed && <img src="/icons/auditing.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>Operation & Device</span>}
                            </div>
                        </>
                    )}

                    {/* ── HARDENING ── */}
                    {canReadHardening && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "hardening-overview" ? "nav-section-active" : ""}`}
                                     onClick={() => navigate("/hardening/overview")}>
                                    <img src="/icons/hardening.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Hardening</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "hardening" ? "active" : ""}`}
                                 onClick={() => navigate("/hardening")} title="Operation and Device">
                                {isSidebarCollapsed && <img src="/icons/hardening.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>Operation & Device</span>}
                            </div>
                        </>
                    )}

                    {/* ── NETWORK DESIGN ── */}
                    {(canReadTopology || canReadArchValidation || canReadDesignConfig || canReadDeployment || canReadDrift) && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className="nav-section">
                                    <img src="/icons/topology.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">Network Design</span>
                                </div>
                            )}
                            {canReadTopology && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "topology" ? "active" : ""}`}
                                     onClick={() => navigate("/topology")} title="Topology">
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Topology</span>}
                                </div>
                            )}
                            {canReadArchValidation && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "architecture-validation" ? "active" : ""}`}
                                     onClick={() => navigate("/architecture-validation")} title="Architecture Validation">
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Architecture Validation</span>}
                                </div>
                            )}
                            {canReadDesignConfig && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "design-configuration" ? "active" : ""}`}
                                     onClick={() => navigate("/design-configuration")} title="Design">
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Design</span>}
                                </div>
                            )}
                            {canReadDesignConfig && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "design-configuration-jobs" ? "active" : ""}`}
                                     onClick={() => navigate("/design-configuration/jobs")} title="Configuration Jobs">
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Configuration Jobs</span>}
                                </div>
                            )}
                            {canReadDeployment && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "deployment" ? "active" : ""}`}
                                     onClick={() => navigate("/deployment/jobs")} title="Deployment">
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Deployment</span>}
                                </div>
                            )}
                            {canReadDrift && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "drift" ? "active" : ""}`}
                                     onClick={() => navigate("/drift")} title="Configuration Drift">
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>Configuration Drift</span>}
                                </div>
                            )}
                        </>
                    )}

                    {/* ── RISK INTELLIGENCE ── */}
                    {!isSidebarCollapsed && (
                        <div className={`nav-section nav-section-clickable ${activeMenu === "risk-intelligence" ? "nav-section-active" : ""}`}
                             onClick={() => navigate("/risk/overview")}>
                            <img src="/icons/risk.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">Risk Intelligence</span>
                        </div>
                    )}
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "risk-asset" ? "active" : ""}`}
                         onClick={() => navigate("/risk/assets")} title="Risk Asset">
                        {isSidebarCollapsed && <img src="/icons/risk.svg" alt="" className="nav-icon-img" />}
                        {!isSidebarCollapsed && <span>Risk Asset</span>}
                    </div>

                    {/* ── SYSTEM ── */}
                    {!isSidebarCollapsed && (
                        <div className="nav-section">
                            <img src="/icons/administration.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">System</span>
                        </div>
                    )}
                    {canReadSysConfig && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "system-configuration" ? "active" : ""}`}
                             onClick={() => navigate("/settings/system")} title="System Configuration">
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>System Configuration</span>}
                        </div>
                    )}
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "licence" ? "active" : ""}`}
                         onClick={() => navigate("/settings/license")} title="License management">
                        {isSidebarCollapsed && <img src="/icons/license.svg" alt="" className="nav-icon-img nav-icon-license" />}
                        {!isSidebarCollapsed && <span>License management</span>}
                    </div>
                    {canReadUserMgmt && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "user-management" ? "active" : ""}`}
                             onClick={() => navigate("/settings/users")} title="User Management">
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>User Management</span>}
                        </div>
                    )}
                    {canReadLogs && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "system-logs" ? "active" : ""}`}
                             onClick={() => navigate("/settings/logs")} title="Logs">
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>Logs</span>}
                        </div>
                    )}
                    {canReadBackup && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "backup" ? "active" : ""}`}
                             onClick={() => navigate("/backup")} title="Configuration Backup">
                            {isSidebarCollapsed && (
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                                     className="nav-icon-img" style={{ flexShrink: 0 }}>
                                    <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
                                    <polyline points="17 21 17 13 7 13 7 21" />
                                    <polyline points="7 3 7 8 15 8" />
                                </svg>
                            )}
                            {!isSidebarCollapsed && <span>Configuration Backup</span>}
                        </div>
                    )}

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
                    <div className="header-left">
                        {/* Decorative brand mark; sits with the page title on every page. */}
                        <span className="header-eye" aria-hidden="true">
                            <img src="/icons/eye.png" alt="" />
                        </span>
                        <div>
                            <h1 className="page-title">
                                {pageTitles[activeMenu] || "Dashboard"}
                            </h1>
                            {pageSubtitles[activeMenu] && (
                                <p className="page-subtitle">{pageSubtitles[activeMenu]}</p>
                            )}
                        </div>
                    </div>
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

                {/* Active route renders here */}
                <Outlet />
            </main>

            {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}
        </div>
    );
};
