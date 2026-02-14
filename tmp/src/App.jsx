import "./assets/Login.css";
import "./assets/Dashboard.css";
import "./assets/UserManagement.css";
import "./assets/AssetList.css";
import "./assets/AssetRequirement.css";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Login } from "./components/Login.jsx";
import { Dashboard } from "./components/Dashboard.jsx";
import { ProtectedRoute } from "./components/ProtectedRoute.jsx";
import { Provider } from "react-redux";
import { store } from "./store/index";

function App() {
    return (
        <Provider store={store}>
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
        </Provider>
    );
}

export default App;