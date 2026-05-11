import "./assets/Login.css";
import "./assets/Dashboard.css";
import "./assets/UserManagement.css";
import "./assets/AssetList.css";
import "./assets/AssetRequirement.css";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Login } from "./components/Login.jsx";
import { Dashboard } from "./components/Dashboard.jsx";
import { ProtectedRoute } from "./components/ProtectedRoute.jsx";
import { LicenseActivationScreen } from "./components/License/LicenseActivationScreen.jsx";
import QuotaExhaustedModal from './components/License/QuotaExhaustedModal';
import {PermissionToast} from "./components/UserManagement/Permissiontoast.jsx";
import { Provider, useDispatch, useSelector } from "react-redux";
import { store } from "./store/index";
import { useEffect, useState } from "react";
import { getLicenseStatusThunk } from "./store/licenseSlice";

function AppContent() {
    const dispatch = useDispatch();
    const { isValid, isValidating } = useSelector((state) => state.license);
    const [licenseChecked, setLicenseChecked] = useState(false);

    // چک کردن وضعیت لایسنس در startup
    useEffect(() => {
        dispatch(getLicenseStatusThunk()).finally(() => {
            setLicenseChecked(true);
        });
    }, [dispatch]);

    // نمایش loading تا زمانی که لایسنس چک شود
    if (!licenseChecked) {
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

                    {/* صفحه داشبورد - محافظت شده */}
                    <Route
                        path="/dashboard"
                        element={
                            <ProtectedRoute>
                                <Dashboard />
                            </ProtectedRoute>
                        }
                    />
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
