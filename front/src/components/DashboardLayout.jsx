/**
 * The application shell: sidebar menu (each entry shown only with its read permission), header
 * with the alert bell, language switch and user menu, the forced password-change and two-step setup dialogs,
 * maintenance overlay, license dialogs, and the page itself in <Outlet/>.
 */
import React, { Suspense } from 'react';
import { useSelector, useDispatch } from "react-redux";
import { logoutUser, mfaEnrolmentRequired, recoveryWarningSeen } from "../store/authSlice";
import { getLicenseStatusThunk } from "../store/licenseSlice";
import { useNavigate, useLocation, Outlet } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import LicenseBadge from './License/LicenseBadge';
import { ChangePasswordModal } from "./ChangePasswordModal";
import { TwoStepAccount, TwoStepSetup } from "./TwoStep";
import { IdleLogout } from "./IdleLogout";
import { AlertBell } from "./Alerts/AlertBell";
import { useAlertSummary } from "./Alerts/useAlertSummary";
import "../assets/Alerts.css";

import "../assets/Dashboard.css";
import api from "../config/api";
import { currentLanguage, hasStoredLanguage, isRtl, LANGUAGES, setLanguage, t, uiLocale } from "../i18n";
import { formatLongDate } from "../utils/dates";
import { SidebarNav } from "./SidebarNav";
import { menuFromPath } from "./sidebarMenu";

export const DashboardLayout = () => {
    const { username, role, permissions } = useSelector((state) => state.auth);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { pathname } = useLocation();
    const activeMenu = menuFromPath(pathname);

    const [currentTime, setCurrentTime] = useState(new Date());
    // On a phone-sized screen the menu starts as the icon rail, so the page keeps the width.
    const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(
        () => typeof window !== "undefined" && !!window.matchMedia?.("(max-width: 640px)").matches);
    const [showDropdown, setShowDropdown] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const mustChangePassword = useSelector((state) => state.auth.mustChangePassword);
    // Two-step sign-in required and not set up: only its setup is shown. The dialog stays open
    // after it is turned on (the flag clears) until the recovery codes are saved.
    const mfaEnrolmentDue = useSelector((state) => state.auth.mfaEnrolmentDue);
    const recoveryCodesLeft = useSelector((state) => state.auth.recoveryCodesLeft);
    const [forcedSetup, setForcedSetup] = useState(false);
    const [showTwoStep, setShowTwoStep] = useState(false);
    if (mfaEnrolmentDue && !mustChangePassword && !forcedSetup) setForcedSetup(true);
    const dropdownRef = useRef(null);

    const { summary: alertSummary, refresh: refreshAlerts } = useAlertSummary();

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

    // The grace period ended while signed in: the server refused a request (api.js).
    useEffect(() => {
        const onRequired = () => dispatch(mfaEnrolmentRequired());
        window.addEventListener("mfa-enrolment-required", onRequired);
        return () => window.removeEventListener("mfa-enrolment-required", onRequired);
    }, [dispatch]);

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

    // Pages where the license's asset limit matters show the plan and the
    // assets used against it.
    const menuToModule = {
        "hardening":        "hardening",
        "operation-device": "auditing",
        "asset-list":       "assets",
        "auto-discovery":   "assets",
        "licence":          "assets",
    };
    const currentModule = menuToModule[activeMenu] || "";

    const handleLogout = async () => {
        await dispatch(logoutUser());
        navigate("/");
    };

    const pageTitles = {
        "dashboard":           t("Dashboard"),
        "asset-management":    t("Asset overview"),
        "asset-requirement":   t("Asset security requirements"),
        "asset-list":          t("Asset List"),
        "software":            t("Software"),
        "auto-discovery":      t("Auto Discovery"),
        "schedule-discovery":  t("Discovery schedules"),
        "auditing":            t("Audit overview"),
        "schedule-auditing":   t("Audit schedules"),
        "operation-device":    t("Run audits"),
        "hardening":           t("Run hardening"),
        "hardening-overview":  t("Hardening overview"),
        "risk-intelligence":   t("Risk overview"),
        "risk-asset":          t("Risk Asset"),
        "remediation":         t("Remediation"),
        "remediation-acceptances": t("Accepted Risks"),
        "reports":             t("Build a report"),
        "reports-archive":     t("Report archive"),
        "reports-schedules":   t("Report schedules"),
        "backup-overview":     t("Device configuration backups"),
        "backup":              t("Device Backups"),
        "backup-restores":     t("Restore History"),
        "topology":            t("Topology"),
        "design-suggestion":   t("Suggested Design"),
        "architecture-validation": t("Architecture Validation"),
        "design-configuration": t("Design & Configuration"),
        "cve":                 t("Vulnerabilities (CVE)"),
        "cve-database":        t("Vulnerability database"),
        "noc-dashboard":       t("Network status (NOC)"),
        "noc-hosts":           t("Hosts"),
        "user-management":     t("User Management"),
        "system-logs":         t("Logs and audit trail"),
        "audit-trail":         t("Logs and audit trail"),
        "system-configuration": t("System Configuration"),
        "system-backup":       t("NGCorion system backup"),
        "notifications":       t("Alert and notification rules"),
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
            <IdleLogout />
            {/* ── SIDEBAR ── */}
            <aside className={`sidebar ${isSidebarCollapsed ? "collapsed" : ""}`}>
                <div className="sidebar-header">
                    {!isSidebarCollapsed && <img src="/logowhite.png" alt="logo" className="sidebar-logo" />}
                    {isSidebarCollapsed  && <img src="/logowhite.png" alt="logo" className="sidebar-logo-small" />}
                    <button className="toggle-sidebar-btn" onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}>
                        {isSidebarCollapsed === isRtl() ? "‹" : "›"}
                    </button>
                </div>

                <SidebarNav auth={{ role, permissions }} username={username} pageKey={activeMenu}
                            collapsed={isSidebarCollapsed} alertSummary={alertSummary} />

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
                                        <button className="user-menu-dropdown-btn action-primary"
                                                onClick={() => { setShowTwoStep(true); setShowDropdown(false); }}>
                                            <i className="fa-solid fa-shield-halved"></i> {" "}{t("Two-step sign-in")}
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
                        {currentModule && <LicenseBadge />}
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
                    {/* Until a password chosen by someone else is replaced, the
                        backend refuses every page's requests: show none. */}
                    {!mustChangePassword && !mfaEnrolmentDue && <Outlet />}
                </Suspense>
            </main>

            {showChangePassword && !mustChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}
            {mustChangePassword && <ChangePasswordModal forced onClose={() => {}} />}
            {forcedSetup && !mustChangePassword && (
                <TwoStepSetup forced username={username} onClose={() => setForcedSetup(false)} />
            )}
            {showTwoStep && !forcedSetup && <TwoStepAccount username={username} onClose={() => setShowTwoStep(false)} />}
            {recoveryCodesLeft !== null && !forcedSetup && (
                <div className="ts-overlay" onClick={() => dispatch(recoveryWarningSeen())}>
                    <div className="ts-dialog ts-dialog-sm" role="alertdialog" aria-modal="true" aria-labelledby="ts-rc-title"
                         onClick={(e) => e.stopPropagation()}>
                        <div className="ts-head">
                            <div className="ts-head-icon warn" aria-hidden="true"><i className="fa-solid fa-key" /></div>
                            <div>
                                <h2 id="ts-rc-title">{t("You signed in with a recovery code")}</h2>
                                <p className="ts-sub">{t("Recovery codes left: {{left}} of {{all}}", { left: recoveryCodesLeft, all: 8 })}</p>
                            </div>
                        </div>
                        <div className="ts-body">
                            <p className="ts-p">{t("If your phone is lost, move two-step sign-in to a new phone now, and make new recovery codes before they run out.")}</p>
                            <div className="ts-actions">
                                <button type="button" className="ts-btn ts-btn-ghost" onClick={() => dispatch(recoveryWarningSeen())}>{t("Later")}</button>
                                <button type="button" className="ts-btn ts-btn-primary"
                                        onClick={() => { dispatch(recoveryWarningSeen()); setShowTwoStep(true); }}>
                                    {t("Open two-step sign-in")}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
