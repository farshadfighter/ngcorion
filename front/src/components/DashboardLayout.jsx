import React, { Suspense } from 'react';
import { useSelector, useDispatch } from "react-redux";
import { logout } from "../store/authSlice";
import { getLicenseStatusThunk } from "../store/licenseSlice";
import { useNavigate, useLocation, Outlet } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import LicenseBadge from './License/LicenseBadge';
import { ChangePasswordModal } from "./ChangePasswordModal";
import { usePermission } from "../hooks/usePermission";
import { AlertBell } from "./Alerts/AlertBell";
import { useAlertSummary } from "./Alerts/useAlertSummary";
import "../assets/Alerts.css";

import "../assets/Dashboard.css";
import api from "../config/api";
import { currentLanguage, hasStoredLanguage, isRtl, LANGUAGES, n, setLanguage, t, uiLocale } from "../i18n";
import { formatLongDate } from "../utils/dates";

// Map the current URL path to a stable menu key. That key drives the sidebar
// active state, the header title and the license badge — reusing the same keys
// the sidebar used back when this was state-based view switching.
const menuFromPath = (pathname) => {
    if (pathname.startsWith("/assets/requirements")) return "asset-requirement";
    if (pathname.startsWith("/assets/inventory"))    return "asset-list";
    if (pathname.startsWith("/assets/discovery"))     return "auto-discovery";
    if (pathname.startsWith("/assets/schedule-discovery")) return "schedule-discovery";
    if (pathname.startsWith("/assets"))               return "asset-management";
    if (pathname.startsWith("/audit/sessions"))       return "operation-device";
    if (pathname.startsWith("/audit/schedule-auditing")) return "schedule-auditing";
    if (pathname.startsWith("/audit"))                return "auditing";
    // More specific first: /hardening/overview must not fall through to the
    // Operation & Device sub-item.
    if (pathname.startsWith("/hardening/overview"))   return "hardening-overview";
    if (pathname.startsWith("/hardening"))            return "hardening";
    if (pathname.startsWith("/backup/overview"))      return "backup-overview";
    if (pathname.startsWith("/backup/restores"))      return "backup-restores";
    if (pathname.startsWith("/backup"))               return "backup";
    if (pathname.startsWith("/topology"))             return "topology";
    if (pathname.startsWith("/design-suggestion"))    return "design-suggestion";
    if (pathname.startsWith("/architecture-validation")) return "architecture-validation";
    if (pathname.startsWith("/design-configuration"))    return "design-configuration";
    if (pathname.startsWith("/cve/database"))         return "cve-database";
    if (pathname.startsWith("/cve"))                  return "cve";
    if (pathname.startsWith("/noc/dashboard"))        return "noc-dashboard";
    if (pathname.startsWith("/noc/hosts"))            return "noc-hosts";
    if (pathname.startsWith("/settings/users"))       return "user-management";
    if (pathname.startsWith("/settings/logs"))        return "system-logs";
    if (pathname.startsWith("/settings/license"))     return "licence";
    if (pathname.startsWith("/settings/system"))      return "system-configuration";
    if (pathname.startsWith("/settings/notifications")) return "notifications";
    if (pathname.startsWith("/alerts"))               return "alerts";
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
    const canReadCve       = usePermission("cve",                   "read");
    const canReadNoc       = usePermission("noc",                   "read");
    const { summary: alertSummary, refresh: refreshAlerts } = useAlertSummary();
    const unacknowledged = alertSummary?.unacknowledged || 0;

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

    // Follow the language saved on the account. A user who never picked one
    // keeps the language chosen on the sign-in page, and it is saved for them.
    const { language: accountLanguage, languageChosen } = useSelector((state) => state.auth);
    useEffect(() => {
        if (!accountLanguage || accountLanguage === currentLanguage()) return;
        if (!languageChosen && hasStoredLanguage()) {
            api.put("/auth/me/language", { language: currentLanguage() }).catch(() => {});
        } else {
            setLanguage(accountLanguage);
        }
    }, [accountLanguage, languageChosen]);

    const chooseLanguage = (code) => {
        setShowDropdown(false);
        if (code === currentLanguage()) return;
        api.put("/auth/me/language", { language: code })
            .catch(() => {})
            .finally(() => setLanguage(code));
    };

    const currentDate = formatLongDate(currentTime);
    const currentTimeString = currentTime.toLocaleTimeString(uiLocale(),  {
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
        "dashboard":           t("Dashboard"),
        "asset-management":    t("Asset Management"),
        "asset-requirement":   t("Asset Requirement"),
        "asset-list":          t("Asset List"),
        "auto-discovery":      t("Auto Discovery"),
        "schedule-discovery":  t("Schedule Discovery"),
        "auditing":            t("Auditing"),
        "schedule-auditing":   t("Schedule Auditing"),
        "operation-device":    t("Operation and Device"),
        "hardening":           t("Hardening"),
        "hardening-overview":  t("Hardening"),
        "hardening-operation": t("Operation and Device"),
        "risk-intelligence":   t("Risk Intelligence"),
        "risk-asset":          t("Risk Asset"),
        "backup-overview":     t("Backup & Restore"),
        "backup":              t("Device Backups"),
        "backup-restores":     t("Restore History"),
        "topology":            t("Topology"),
        "design-suggestion":   t("Suggested Design"),
        "architecture-validation": t("Architecture Validation"),
        "design-configuration": t("Design & Configuration"),
        "cve":                 t("CVE Findings"),
        "cve-database":        t("CVE Database"),
        "noc-dashboard":       t("NOC Dashboard"),
        "noc-hosts":           t("NOC Host"),
        "user-management":     t("User Management"),
        "system-logs":         t("System Logs"),
        "system-configuration": t("System Configuration"),
        "notifications":       t("Notifications"),
        "alerts":              t("Alerts"),
        "licence":             t("License Management"),
    };

    // One-line explanation shown under the page title.
    const pageSubtitles = {
        "topology": t("The network as it actually is right now - every real asset and the cabling between them."),
        "design-suggestion": t("A standard Cisco SAFE campus design sized to your real asset inventory, with matching assets slotted in - review it, then turn it into a real Design."),
        "architecture-validation": t("Automated checks against the current topology (redundancy, exposure, best practice)."),
        "design-configuration": t("Draw a planned blueprint here, even for devices that don't exist yet. Versioned, so you can compare a design's history over time."),
        "noc-dashboard": t("Live SNMP status for every asset, plotted on the same topology graph as Topology."),
        "noc-hosts": t("Every asset, searchable - open one to see its SNMP details and set up monitoring."),
    };

    return (
        <div className="dashboard-container">
            {/* ── SIDEBAR ── */}
            <aside className={`sidebar ${isSidebarCollapsed ? "collapsed" : ""}`}>
                <div className="sidebar-header">
                    {!isSidebarCollapsed && <img src="/logowhite.png" alt="logo" className="sidebar-logo" />}
                    {isSidebarCollapsed  && <img src="/logowhite.png" alt="logo" className="sidebar-logo-small" />}
                    <button className="toggle-sidebar-btn" onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}>
                        {isSidebarCollapsed === isRtl() ? "‹" : "›"}
                    </button>
                </div>

                <nav className="sidebar-nav">

                    {/* ── Dashboard ── */}
                    <div className={`nav-item ${activeMenu === "dashboard" ? "active" : ""}`}
                         onClick={() => navigate("/overview")} title={t("Dashboard")}>
                        <img src="/icons/dashboard.svg" alt="" className="nav-icon-img" />
                        {!isSidebarCollapsed && <span>{t("Dashboard")}</span>}
                    </div>

                    {/* ── Alerts ── */}
                    <div className={`nav-item ${activeMenu === "alerts" ? "active" : ""}`}
                         onClick={() => navigate("/alerts")}
                         title={unacknowledged ? t("Alerts - {{unacknowledged}} not acknowledged", { unacknowledged }) : t("Alerts")}>
                        <img src="/icons/alerts.svg" alt="" className="nav-icon-img" />
                        {!isSidebarCollapsed && <span>{t("Alerts")}</span>}
                        {!isSidebarCollapsed && unacknowledged > 0 && (
                            <span className={`alr-nav-badge ${alertSummary?.critical ? "" : "is-calm"}`}
                                  aria-label={t("{{unacknowledged}} not acknowledged", { unacknowledged })}>
                                {unacknowledged > 99 ? n("99+") : n(unacknowledged)}
                            </span>
                        )}
                    </div>

                    {/* ── ASSET MANAGEMENT ── */}
                    {(canReadAssetReq || canReadAssetList || canReadAutoDisc || canReadAuditing) && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "asset-management" ? "nav-section-active" : ""}`}
                                     onClick={() => navigate("/assets")}>
                                    <img src="/icons/asset-management.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">{t("Asset Management")}</span>
                                </div>
                            )}
                            {canReadAssetReq && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-requirement" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/requirements")} title={t("Asset Requirement")}>
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Asset Requirement")}</span>}
                                </div>
                            )}
                            {canReadAssetList && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "asset-list" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/inventory")} title={t("Asset List")}>
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Asset List")}</span>}
                                </div>
                            )}
                            {canReadAutoDisc && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "auto-discovery" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/discovery")} title={t("Auto Discovery")}>
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Auto Discovery")}</span>}
                                </div>
                            )}
                            {canReadAutoDisc && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "schedule-discovery" ? "active" : ""}`}
                                     onClick={() => navigate("/assets/schedule-discovery")} title={t("Schedule Discovery")}>
                                    {isSidebarCollapsed && <img src="/icons/asset-management.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Schedule Discovery")}</span>}
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
                                    <span className="nav-section-title">{t("Auditing")}</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "operation-device" ? "active" : ""}`}
                                 onClick={() => navigate("/audit/sessions")} title={t("Operation & Device")}>
                                {isSidebarCollapsed && <img src="/icons/auditing.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Operation & Device")}</span>}
                            </div>
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "schedule-auditing" ? "active" : ""}`}
                                 onClick={() => navigate("/audit/schedule-auditing")} title={t("Schedule Auditing")}>
                                {isSidebarCollapsed && <img src="/icons/auditing.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Schedule Auditing")}</span>}
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
                                    <span className="nav-section-title">{t("Hardening")}</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "hardening" ? "active" : ""}`}
                                 onClick={() => navigate("/hardening")} title={t("Operation and Device")}>
                                {isSidebarCollapsed && <img src="/icons/hardening.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Operation & Device")}</span>}
                            </div>
                        </>
                    )}

                    {/* ── BACKUP & RESTORE ── */}
                    {canReadBackup && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "backup-overview" ? "nav-section-active" : ""}`}
                                     onClick={() => navigate("/backup/overview")}>
                                    <img src="/icons/backup.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">{t("Backup & Restore")}</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "backup-overview" ? "active" : ""}`}
                                 onClick={() => navigate("/backup/overview")} title={t("Backup Overview")}>
                                {isSidebarCollapsed && <img src="/icons/backup.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Overview")}</span>}
                            </div>
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "backup" ? "active" : ""}`}
                                 onClick={() => navigate("/backup")} title={t("Device Backups")}>
                                {isSidebarCollapsed && <img src="/icons/backup.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Device Backups")}</span>}
                            </div>
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "backup-restores" ? "active" : ""}`}
                                 onClick={() => navigate("/backup/restores")} title={t("Restore History")}>
                                {isSidebarCollapsed && <img src="/icons/backup.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Restore History")}</span>}
                            </div>
                        </>
                    )}

                    {/* ── NETWORK DESIGN ── */}
                    {(canReadTopology || canReadArchValidation || canReadDesignConfig) && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className="nav-section">
                                    <img src="/icons/topology.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">{t("Network Design")}</span>
                                </div>
                            )}
                            {canReadTopology && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "topology" ? "active" : ""}`}
                                     onClick={() => navigate("/topology")} title={t("Topology")}>
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Topology")}</span>}
                                </div>
                            )}
                            {canReadDesignConfig && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "design-suggestion" ? "active" : ""}`}
                                     onClick={() => navigate("/design-suggestion")} title={t("Suggested Design")}>
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Suggested Design")}</span>}
                                </div>
                            )}
                            {canReadArchValidation && (
                                <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "architecture-validation" ? "active" : ""}`}
                                     onClick={() => navigate("/architecture-validation")} title={t("Architecture Validation")}>
                                    {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                    {!isSidebarCollapsed && <span>{t("Architecture Validation")}</span>}
                                </div>
                            )}
                            {/* Design, Configuration Jobs, Deployment and Configuration Drift have
                                no sidebar entry point (product decision). Configuration Jobs,
                                Deployment and Drift have no code left in the app at all. Design
                                (DesignList/DesignDetail/DesignCanvas + designSlice) is the one
                                exception - it's kept, routable but unlisted, because Suggested
                                Design's "Create this design" button still needs somewhere to
                                send a newly created design. */}
                        </>
                    )}

                    {/* ── NOC ── */}
                    {canReadNoc && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "noc-dashboard" ? "nav-section-active" : ""}`}
                                     onClick={() => navigate("/noc/dashboard")}>
                                    <img src="/icons/topology.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">{t("NOC")}</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "noc-dashboard" ? "active" : ""}`}
                                 onClick={() => navigate("/noc/dashboard")} title={t("Dashboard")}>
                                {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Dashboard")}</span>}
                            </div>
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "noc-hosts" ? "active" : ""}`}
                                 onClick={() => navigate("/noc/hosts")} title={t("Host")}>
                                {isSidebarCollapsed && <img src="/icons/topology.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Host")}</span>}
                            </div>
                        </>
                    )}

                    {/* ── RISK INTELLIGENCE ── */}
                    {!isSidebarCollapsed && (
                        <div className={`nav-section nav-section-clickable ${activeMenu === "risk-intelligence" ? "nav-section-active" : ""}`}
                             onClick={() => navigate("/risk/overview")}>
                            <img src="/icons/risk.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">{t("Risk Intelligence")}</span>
                        </div>
                    )}
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "risk-asset" ? "active" : ""}`}
                         onClick={() => navigate("/risk/assets")} title={t("Risk Asset")}>
                        {isSidebarCollapsed && <img src="/icons/risk.svg" alt="" className="nav-icon-img" />}
                        {!isSidebarCollapsed && <span>{t("Risk Asset")}</span>}
                    </div>

                    {/* ── CVE VULNERABILITY MANAGEMENT ── */}
                    {canReadCve && (
                        <>
                            {!isSidebarCollapsed && (
                                <div className={`nav-section nav-section-clickable ${activeMenu === "cve" ? "nav-section-active" : ""}`}
                                     onClick={() => navigate("/cve")}>
                                    <img src="/icons/cve.svg" alt="" className="section-icon" />
                                    <span className="nav-section-title">{t("CVE")}</span>
                                </div>
                            )}
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "cve" ? "active" : ""}`}
                                 onClick={() => navigate("/cve")} title={t("CVE Findings")}>
                                {isSidebarCollapsed && <img src="/icons/cve.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Findings")}</span>}
                            </div>
                            <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "cve-database" ? "active" : ""}`}
                                 onClick={() => navigate("/cve/database")} title={t("CVE Database")}>
                                {isSidebarCollapsed && <img src="/icons/cve.svg" alt="" className="nav-icon-img" />}
                                {!isSidebarCollapsed && <span>{t("Database")}</span>}
                            </div>
                        </>
                    )}

                    {/* ── SYSTEM ── */}
                    {!isSidebarCollapsed && (
                        <div className="nav-section">
                            <img src="/icons/administration.svg" alt="" className="section-icon" />
                            <span className="nav-section-title">{t("System")}</span>
                        </div>
                    )}
                    {canReadSysConfig && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "system-configuration" ? "active" : ""}`}
                             onClick={() => navigate("/settings/system")} title={t("System Configuration")}>
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>{t("System Configuration")}</span>}
                        </div>
                    )}
                    {canReadSysConfig && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "notifications" ? "active" : ""}`}
                             onClick={() => navigate("/settings/notifications")} title={t("Notifications")}>
                            {isSidebarCollapsed && <img src="/icons/alerts.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>{t("Notifications")}</span>}
                        </div>
                    )}
                    <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "licence" ? "active" : ""}`}
                         onClick={() => navigate("/settings/license")} title={t("License management")}>
                        {isSidebarCollapsed && <img src="/icons/license.svg" alt="" className="nav-icon-img nav-icon-license" />}
                        {!isSidebarCollapsed && <span>{t("License management")}</span>}
                    </div>
                    {canReadUserMgmt && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "user-management" ? "active" : ""}`}
                             onClick={() => navigate("/settings/users")} title={t("User Management")}>
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>{t("User Management")}</span>}
                        </div>
                    )}
                    {canReadLogs && (
                        <div className={`nav-item ${isSidebarCollapsed ? "" : "sub-item"} ${activeMenu === "system-logs" ? "active" : ""}`}
                             onClick={() => navigate("/settings/logs")} title={t("Logs")}>
                            {isSidebarCollapsed && <img src="/icons/administration.svg" alt="" className="nav-icon-img" />}
                            {!isSidebarCollapsed && <span>{t("Logs")}</span>}
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
                                            <i className="fa-solid fa-key"></i> {" "}{t("Change Password")}
                                        </button>
                                        <div className="user-menu-lang" role="group" aria-label={t("Language")}>
                                            <span className="user-menu-lang-label">{t("Language")}</span>
                                            {LANGUAGES.map((l) => (
                                                <button key={l.code} type="button" lang={l.code} dir={l.dir}
                                                        aria-pressed={currentLanguage() === l.code}
                                                        className={`user-menu-dropdown-btn user-menu-lang-btn ${currentLanguage() === l.code ? "is-on" : ""}`}
                                                        onClick={() => chooseLanguage(l.code)}>
                                                    {l.label}
                                                    {currentLanguage() === l.code && <i className="fa-solid fa-check" aria-hidden="true"></i>}
                                                </button>
                                            ))}
                                        </div>
                                        <button className="user-menu-dropdown-btn action-danger" onClick={handleLogout}>
                                            <i className="fa-solid fa-right-from-bracket"></i> {" "}{t("Logout")}
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
                                {pageTitles[activeMenu] || t("Dashboard")}
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
                        <AlertBell summary={alertSummary} onChanged={refreshAlerts} />
                        <div className="date-time">
                            <div className="current-date">{currentDate}</div>
                            <div className="current-time" style={{ paddingInlineStart: "25px" }}>
                                <img src="/icons/watch.png" style={{ width: "15px", height: "15px", margin: "15px 8px -1px 1px" }} alt="clock" />
                                {currentTimeString}
                            </div>
                        </div>
                    </div>
                </header>

                {/* Active route renders here */}
                {/* Pages are loaded on first visit; the layout stays while one loads. */}
                <Suspense fallback={<div className="page-loading" role="status" aria-live="polite">{t("Loading…")}</div>}>
                    <Outlet />
                </Suspense>
            </main>

            {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}
        </div>
    );
};
