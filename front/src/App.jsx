import "./assets/Login.css";
import "./assets/Dashboard.css";
import "./assets/UserManagement.css";
import "./assets/AssetList.css";
import "./assets/AssetRequirement.css";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { Login } from "./components/Login.jsx";
import { ForgotPassword } from "./components/ForgotPassword.jsx";
import { ResetPassword } from "./components/ResetPassword.jsx";
import { DashboardLayout } from "./components/DashboardLayout.jsx";
import { ProtectedRoute } from "./components/ProtectedRoute.jsx";
import { LicenseActivationScreen } from "./components/License/LicenseActivationScreen.jsx";
import QuotaExhaustedModal from './components/License/QuotaExhaustedModal';
import {PermissionToast} from "./components/UserManagement/Permissiontoast.jsx";

// Pages load on first visit (code splitting); the shell above loads at once.
const AssetRequirement = lazy(() => import("./components/AssetRequirement/AssetRequirement").then((m) => ({ default: m.AssetRequirement })));
const AssetManagementDashboard = lazy(() => import("./components/AssetManagement/AssetManagementDashboard").then((m) => ({ default: m.AssetManagementDashboard })));
const AuditingDashboard = lazy(() => import("./components/Auditing/AuditingDashboard").then((m) => ({ default: m.AuditingDashboard })));
const AuditingList = lazy(() => import("./components/Auditing/AuditingList").then((m) => ({ default: m.AuditingList })));
const UserManagement = lazy(() => import("./components/UserManagement/UserManagement").then((m) => ({ default: m.UserManagement })));
const LogsPage = lazy(() => import("./components/Logs/LogsPage").then((m) => ({ default: m.LogsPage })));
const BackupPage = lazy(() => import("./components/Backup/BackupPage"));
const BackupOverview = lazy(() => import("./components/Backup/BackupOverview").then((m) => ({ default: m.BackupOverview })));
const RestoreHistory = lazy(() => import("./components/Backup/RestoreHistory").then((m) => ({ default: m.RestoreHistory })));
const License = lazy(() => import("./components/License/License").then((m) => ({ default: m.License })));
const RiskAsset = lazy(() => import("./components/Risk/RiskAsset").then((m) => ({ default: m.RiskAsset })));
const RiskIntelDashboard = lazy(() => import("./components/Risk/RiskIntelDashboard").then((m) => ({ default: m.RiskIntelDashboard })));
const AssetRiskDetail = lazy(() => import("./components/Risk/detail/AssetRiskDetail").then((m) => ({ default: m.AssetRiskDetail })));
const HardeningDashboard = lazy(() => import("./components/Hardening/dashboard/HardeningDashboard").then((m) => ({ default: m.HardeningDashboard })));
const OverviewDashboard = lazy(() => import("./components/Overview/OverviewDashboard").then((m) => ({ default: m.OverviewDashboard })));
const SystemConfiguration = lazy(() => import("./components/SystemConfig/SystemConfiguration").then((m) => ({ default: m.SystemConfiguration })));
const TopologyDashboard = lazy(() => import("./components/Topology/TopologyDashboard").then((m) => ({ default: m.TopologyDashboard })));
const ArchitectureValidationDashboard = lazy(() => import("./components/ArchitectureValidation/ArchitectureValidationDashboard").then((m) => ({ default: m.ArchitectureValidationDashboard })));
const DesignList = lazy(() => import("./components/DesignConfiguration/DesignList").then((m) => ({ default: m.DesignList })));
const SuggestedDesign = lazy(() => import("./components/DesignConfiguration/SuggestedDesign").then((m) => ({ default: m.SuggestedDesign })));
const DesignDetail = lazy(() => import("./components/DesignConfiguration/DesignDetail").then((m) => ({ default: m.DesignDetail })));
const DesignCanvas = lazy(() => import("./components/DesignConfiguration/DesignCanvas").then((m) => ({ default: m.DesignCanvas })));
const ScheduledJobsPage = lazy(() => import("./components/Scheduling/ScheduledJobsPage").then((m) => ({ default: m.ScheduledJobsPage })));
const CveFindings = lazy(() => import("./components/CVE/CveFindings").then((m) => ({ default: m.CveFindings })));
const CveDatabase = lazy(() => import("./components/CVE/CveDatabase").then((m) => ({ default: m.CveDatabase })));
const NocDashboard = lazy(() => import("./components/NOC/NocDashboard").then((m) => ({ default: m.NocDashboard })));
const NocHostList = lazy(() => import("./components/NOC/NocHostList").then((m) => ({ default: m.NocHostList })));
const NocHostDetail = lazy(() => import("./components/NOC/NocHostDetail").then((m) => ({ default: m.NocHostDetail })));
import {
    RequirePermission,
    AssetListRoute,
    AutoDiscoveryRoute,
    HardeningRoute,
} from "./components/routePages.jsx";
import { Provider, useDispatch, useSelector } from "react-redux";
import { store } from "./store/index";
import { lazy, useEffect, useState } from "react";
import { getLicenseStatusThunk } from "./store/licenseSlice";
import { verifyToken } from "./store/authSlice";

function AppContent() {
    const dispatch = useDispatch();
    const { isValid } = useSelector((state) => state.license);
    const { authChecked } = useSelector((state) => state.auth);
    const [licenseChecked, setLicenseChecked] = useState(false);

    // چک کردن وضعیت لایسنس در startup
    useEffect(() => {
        dispatch(getLicenseStatusThunk()).finally(() => {
            setLicenseChecked(true);
        });
    }, [dispatch]);

    // Validate the stored token against the backend BEFORE rendering any
    // protected route. verifyToken resolves authChecked either way (valid →
    // stay logged in; missing/expired → session cleared, route to login), so no
    // protected content renders until the session is confirmed. Fixes the
    // "dashboard flash then kicked to login" on load.
    useEffect(() => {
        dispatch(verifyToken());
    }, [dispatch]);

    // نمایش loading تا زمانی که لایسنس چک شود و توکن اعتبارسنجی شود
    if (!licenseChecked || !authChecked) {
        return (
            <div
                style={{
                    minHeight: "100vh",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    backgroundColor: "#F9FAFB",
                }}
            >
                <div style={{ textAlign: "center" }}>
                    <div
                        style={{
                            width: "48px",
                            height: "48px",
                            border: "4px solid #E5E7EB",
                            borderTopColor: "#111827",
                            borderRadius: "50%",
                            animation: "spin 0.8s linear infinite",
                            margin: "0 auto 16px",
                        }}
                    />
                    <div style={{ fontSize: "14px", color: "#6B7280" }}>
                        Checking license...
                    </div>
                </div>
                <style>{`
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                `}</style>
            </div>
        );
    }

    // اگر لایسنس معتبر نیست، صفحه فعال‌سازی را نمایش بده
    if (!isValid) {
        return <LicenseActivationScreen />;
    }

    // اگر لایسنس معتبر است، برنامه را نمایش بده
    return (
        <>
            <BrowserRouter>
                <Routes>
                    {/* صفحه لاگین */}
                    <Route path="/" element={<Login />} />

                    {/* بازیابی رمز عبور */}
                    <Route path="/forgot-password" element={<ForgotPassword />} />
                    <Route path="/reset-password" element={<ResetPassword />} />

                    {/* ── Protected app: shared layout (sidebar + header) with a
                           child route per section, so every section has its own
                           deep-linkable URL. ── */}
                    <Route
                        element={
                            <ProtectedRoute>
                                <DashboardLayout />
                            </ProtectedRoute>
                        }
                    >
                        <Route path="/overview" element={<OverviewDashboard />} />

                        {/* Asset Management */}
                        <Route path="/assets" element={<AssetManagementDashboard />} />
                        <Route path="/assets/requirements" element={
                            <RequirePermission module="asset_requirement" name="Asset Requirement">
                                <AssetRequirement />
                            </RequirePermission>
                        } />
                        <Route path="/assets/inventory" element={
                            <RequirePermission module="asset_list" name="Asset List">
                                <AssetListRoute />
                            </RequirePermission>
                        } />
                        <Route path="/assets/discovery" element={
                            <RequirePermission module="asset_auto_discovery" name="Auto Discovery">
                                <AutoDiscoveryRoute />
                            </RequirePermission>
                        } />

                        {/* Schedule Discovery - lives under Asset Management, not a
                            standalone section (product decision: this is a scheduled
                            variant of Auto Discovery, not a separate feature) */}
                        <Route path="/assets/schedule-discovery" element={
                            <RequirePermission module="asset_auto_discovery" name="Schedule Discovery">
                                <ScheduledJobsPage key="discovery" jobType="discovery" />
                            </RequirePermission>
                        } />

                        {/* Auditing */}
                        <Route path="/audit" element={
                            <RequirePermission module="auditing" name="Auditing">
                                <AuditingDashboard />
                            </RequirePermission>
                        } />
                        <Route path="/audit/sessions" element={
                            <RequirePermission module="auditing" name="Auditing">
                                <AuditingList />
                            </RequirePermission>
                        } />
                        <Route path="/audit/schedule-auditing" element={
                            <RequirePermission module="auditing" name="Schedule Auditing">
                                <ScheduledJobsPage key="audit" jobType="audit" />
                            </RequirePermission>
                        } />
                        <Route path="/audit/sessions/:sessionId" element={
                            <RequirePermission module="auditing" name="Auditing">
                                <AuditingList />
                            </RequirePermission>
                        } />

                        {/* Hardening */}
                        <Route path="/hardening" element={
                            <RequirePermission module="hardening" name="Hardening">
                                <HardeningRoute />
                            </RequirePermission>
                        } />
                        <Route path="/hardening/overview" element={
                            <RequirePermission module="hardening" name="Hardening">
                                <HardeningDashboard />
                            </RequirePermission>
                        } />

                        {/* Backup & Restore */}
                        <Route path="/backup/overview" element={
                            <RequirePermission module="backup" name="Backup & Restore">
                                <BackupOverview />
                            </RequirePermission>
                        } />
                        <Route path="/backup" element={
                            <RequirePermission module="backup" name="Backup & Restore">
                                <BackupPage />
                            </RequirePermission>
                        } />
                        <Route path="/backup/restores" element={
                            <RequirePermission module="backup" name="Backup & Restore">
                                <RestoreHistory />
                            </RequirePermission>
                        } />

                        {/* Network Design */}
                        <Route path="/topology" element={
                            <RequirePermission module="topology" name="Topology">
                                <TopologyDashboard />
                            </RequirePermission>
                        } />
                        <Route path="/design-suggestion" element={
                            <RequirePermission module="design_configuration" name="Suggested Design">
                                <SuggestedDesign />
                            </RequirePermission>
                        } />
                        <Route path="/architecture-validation" element={
                            <RequirePermission module="architecture_validation" name="Architecture Validation">
                                <ArchitectureValidationDashboard />
                            </RequirePermission>
                        } />
                        <Route path="/design-configuration" element={
                            <RequirePermission module="design_configuration" name="Design & Configuration">
                                <DesignList />
                            </RequirePermission>
                        } />
                        <Route path="/design-configuration/designs/:designId" element={
                            <RequirePermission module="design_configuration" name="Design & Configuration">
                                <DesignDetail />
                            </RequirePermission>
                        } />
                        <Route path="/design-configuration/versions/:versionId" element={
                            <RequirePermission module="design_configuration" name="Design & Configuration">
                                <DesignCanvas />
                            </RequirePermission>
                        } />

                        {/* Vulnerability Management */}
                        <Route path="/cve" element={
                            <RequirePermission module="cve" name="CVE">
                                <CveFindings />
                            </RequirePermission>
                        } />
                        <Route path="/cve/database" element={
                            <RequirePermission module="cve" name="CVE">
                                <CveDatabase />
                            </RequirePermission>
                        } />

                        {/* NOC */}
                        <Route path="/noc/dashboard" element={
                            <RequirePermission module="noc" name="NOC Dashboard">
                                <NocDashboard />
                            </RequirePermission>
                        } />
                        <Route path="/noc/hosts" element={
                            <RequirePermission module="noc" name="NOC Host">
                                <NocHostList />
                            </RequirePermission>
                        } />
                        <Route path="/noc/hosts/:assetId" element={
                            <RequirePermission module="noc" name="NOC Host">
                                <NocHostDetail />
                            </RequirePermission>
                        } />

                        {/* System Settings */}
                        <Route path="/settings/users" element={
                            <RequirePermission module="user_management" name="User Management">
                                <UserManagement />
                            </RequirePermission>
                        } />
                        <Route path="/settings/logs" element={
                            <RequirePermission module="logs" name="System Logs">
                                <LogsPage />
                            </RequirePermission>
                        } />
                        <Route path="/settings/license" element={<License />} />
                        <Route path="/settings/system" element={
                            <RequirePermission module="system_config" name="System Configuration">
                                <SystemConfiguration />
                            </RequirePermission>
                        } />
                        {/* Both former pages now live as dialogs inside System Configuration. */}
                        <Route path="/settings/ntp" element={<Navigate to="/settings/system" replace />} />
                        <Route path="/settings/snmp" element={<Navigate to="/settings/system" replace />} />

                        {/* Risk Intelligence */}
                        <Route path="/risk/assets" element={
                            <RequirePermission module="risk" name="Risk Asset">
                                <RiskAsset />
                            </RequirePermission>
                        } />
                        <Route path="/risk/assets/:assetId" element={
                            <RequirePermission module="risk" name="Risk Asset">
                                <AssetRiskDetail />
                            </RequirePermission>
                        } />
                        {/* KPI + charts overview. Not in the sidebar yet — its
                            placement in the menu is still pending in Figma. */}
                        <Route path="/risk/overview" element={
                            <RequirePermission module="risk" name="Risk Intelligence">
                                <RiskIntelDashboard />
                            </RequirePermission>
                        } />
                        {/* Legacy path kept as an alias of the Risk Asset page */}
                        <Route path="/risk/exposure" element={<Navigate to="/risk/assets" replace />} />
                    </Route>

                    {/* Legacy /dashboard → overview, plus catch-all */}
                    <Route path="/dashboard" element={<Navigate to="/overview" replace />} />
                    <Route path="*" element={<Navigate to="/overview" replace />} />
                </Routes>
            </BrowserRouter>

            {/* مودال سهمیه تمام شده - نمایش در تمام صفحات */}
            <PermissionToast />
            <QuotaExhaustedModal />
        </>
    );
}

function App() {
    return (
        <Provider store={store}>
            <AppContent />
        </Provider>
    );
}

export default App;
