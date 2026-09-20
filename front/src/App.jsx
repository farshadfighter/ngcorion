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

import { AssetRequirement } from "./components/AssetRequirement/AssetRequirement";
import { AssetManagementDashboard } from "./components/AssetManagement/AssetManagementDashboard";
import { AuditingDashboard } from "./components/Auditing/AuditingDashboard";
import { AuditingList } from "./components/Auditing/AuditingList";
import { UserManagement } from "./components/UserManagement/UserManagement";
import { LogsPage } from "./components/Logs/LogsPage";
import BackupPage from "./components/Backup/BackupPage";
import { License } from "./components/License/License";
import { RiskAsset } from "./components/Risk/RiskAsset";
import { RiskIntelDashboard } from "./components/Risk/RiskIntelDashboard";
import { AssetRiskDetail } from "./components/Risk/detail/AssetRiskDetail";
import { HardeningDashboard } from "./components/Hardening/dashboard/HardeningDashboard";
import { OverviewDashboard } from "./components/Overview/OverviewDashboard";
import { SystemConfiguration } from "./components/SystemConfig/SystemConfiguration";
import { TopologyDashboard } from "./components/Topology/TopologyDashboard";
import { ArchitectureValidationDashboard } from "./components/ArchitectureValidation/ArchitectureValidationDashboard";
import { DesignList } from "./components/DesignConfiguration/DesignList";
import { DesignDetail } from "./components/DesignConfiguration/DesignDetail";
import { DesignCanvas } from "./components/DesignConfiguration/DesignCanvas";
import { ConfigurationJobList } from "./components/DesignConfiguration/ConfigurationJobList";
import { ConfigurationJobDetail } from "./components/DesignConfiguration/ConfigurationJobDetail";
import { DeploymentJobList } from "./components/Deployment/DeploymentJobList";
import { DeploymentJobDetail } from "./components/Deployment/DeploymentJobDetail";
import { DriftDashboard } from "./components/Drift/DriftDashboard";
import { ScheduledJobsPage } from "./components/Scheduling/ScheduledJobsPage";
import {
    RequirePermission,
    RequireRole,
    AssetListRoute,
    AutoDiscoveryRoute,
    HardeningRoute,
} from "./components/routePages.jsx";
import { Provider, useDispatch, useSelector } from "react-redux";
import { store } from "./store/index";
import { useEffect, useState } from "react";
import { getLicenseStatusThunk } from "./store/licenseSlice";
import { verifyToken } from "./store/authSlice";

function AppContent() {
    const dispatch = useDispatch();
    const { isValid, isValidating } = useSelector((state) => state.license);
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

                        {/* Scheduled Jobs - self-guards on discovery OR auditing read,
                            since it lists both job types */}
                        <Route path="/scheduling" element={<ScheduledJobsPage />} />

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

                        {/* Configuration Backup */}
                        <Route path="/backup" element={
                            <RequirePermission module="backup" name="Configuration Backup">
                                <BackupPage />
                            </RequirePermission>
                        } />

                        {/* Network Design */}
                        <Route path="/topology" element={
                            <RequirePermission module="topology" name="Topology">
                                <TopologyDashboard />
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
                        <Route path="/design-configuration/jobs" element={
                            <RequirePermission module="design_configuration" name="Design & Configuration">
                                <ConfigurationJobList />
                            </RequirePermission>
                        } />
                        <Route path="/design-configuration/jobs/:jobId" element={
                            <RequirePermission module="design_configuration" name="Design & Configuration">
                                <ConfigurationJobDetail />
                            </RequirePermission>
                        } />
                        <Route path="/deployment/jobs" element={
                            <RequireRole roles={["admin", "manager"]} name="Deployment">
                                <DeploymentJobList />
                            </RequireRole>
                        } />
                        <Route path="/deployment/jobs/:jobId" element={
                            <RequireRole roles={["admin", "manager"]} name="Deployment">
                                <DeploymentJobDetail />
                            </RequireRole>
                        } />
                        <Route path="/drift" element={
                            <RequirePermission module="drift" name="Configuration Drift">
                                <DriftDashboard />
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
