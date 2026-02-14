import { useSelector, useDispatch } from "react-redux";
import { logout } from "../store/authSlice";
import { useNavigate } from "react-router-dom";
import { useState ,useEffect} from "react";
import { UserManagement } from "./UserManagement/UserManagement";
import { AssetList } from "./AssetList/AssetList";
import { AssetRequirement } from "./AssetRequirement/AssetRequirement";
import AutoDiscovery from "./AutoDiscovery/AutoDiscovery";

export const Dashboard = () => {
    const { username,role } = useSelector((state) => state.auth);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [activeMenu, setActiveMenu] = useState("dashboard");
    const [currentTime, setCurrentTime] = useState(new Date());
    const handleLogout = () => {
        dispatch(logout());

        navigate("/");
    };



    useEffect(() => {
        const timer = setInterval(() => {
            setCurrentTime(new Date());
        }, 1000);

        return () => clearInterval(timer); // cleanup
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

    return (
        <div className="dashboard-container">
            {/* SIDEBAR */}
            <aside className="sidebar">
                <div className="sidebar-header">
                    <img src="./log.png" alt="logo" className="sidebar-logo" />
                </div>

                <nav className="sidebar-nav">
                    {/* Dashboard */}
                    <div
                        className={`nav-item ${activeMenu === "dashboard" ? "active" : ""}`}
                        onClick={() => setActiveMenu("dashboard")}
                    >
                        <img src="/icons/dashboard.svg" alt="" className="nav-icon-img" />
                        <span>dashboard</span>
                    </div>

                    {/* ASSET MANAGEMENT Section */}
                    <div className="nav-section">
                        <img src="/icons/asset-management.svg" alt="" className="section-icon" />
                        <span className="nav-section-title">ASSET MANAGEMENT</span>
                    </div>
                    <div
                        className={`nav-item sub-item ${activeMenu === "asset-requirement" ? "active" : ""}`}
                        onClick={() => setActiveMenu("asset-requirement")}
                    >
                        <span>Asset Requirement</span>
                    </div>
                    <div
                        className={`nav-item sub-item ${activeMenu === "asset-list" ? "active" : ""}`}
                        onClick={() => setActiveMenu("asset-list")}
                    >
                        <span>Asset List</span>
                    </div>
                    <div
                        className={`nav-item sub-item ${activeMenu === "auto-discovery" ? "active" : ""}`}
                        onClick={() => setActiveMenu("auto-discovery")}
                    >
                        <span>Auto Discovery</span>
                    </div>

                    {/* Auditing */}
                    <div
                        className={`nav-item ${activeMenu === "auditing" ? "active" : ""}`}
                        onClick={() => setActiveMenu("auditing")}
                    >
                        <img src="/icons/auditing.svg" alt="" className="nav-icon-img" />
                        <span>Auditing</span>
                    </div>
                    <div
                        className={`nav-item sub-item ${activeMenu === "operation-device" ? "active" : ""}`}
                        onClick={() => setActiveMenu("operation-device")}
                    >
                        <span>Operation and Device</span>
                    </div>


                    {/* Hardening */}
                    <div
                        className={`nav-item ${activeMenu === "hardening" ? "active" : ""}`}
                        onClick={() => setActiveMenu("hardening")}
                    >
                        <img src="/icons/hardening.svg" alt="" className="nav-icon-img" />
                        <span>Hardening</span>
                    </div>

                    {/* ADMINISTRATION Section */}
                    <div className="nav-section">
                        <img src="/icons/administration.svg" alt="" className="section-icon" />
                        <span className="nav-section-title">Administration</span>
                    </div>
                    <div
                        className={`nav-item sub-item ${activeMenu === "user-management" ? "active" : ""}`}
                        onClick={() => setActiveMenu("user-management")}
                    >
                        <span>User Management</span>
                    </div>
                    <div
                        className={`nav-item sub-item ${activeMenu === "logs" ? "active" : ""}`}
                        onClick={() => setActiveMenu("logs")}
                    >
                        <span>Logs</span>
                    </div>
                </nav>

                <div className="sidebar-footer">
                    <div className="user-info">
                        <div className="user-avatar">
                            {username?.charAt(0).toUpperCase()}
                        </div>
                        <div className="user-details">
                            <div className="user-name">{username}</div>
                            <div className="user-role">{role}</div>
                        </div>
                    </div>
                    <button className="logout-btn" onClick={handleLogout}>
                        ⋮
                    </button>
                </div>
            </aside>

            {/* MAIN CONTENT */}
            <main className="main-content">
                <header className="dashboard-header">
                    <h1 className="page-title">
                        {activeMenu === "dashboard" && "Dashboard"}
                        {activeMenu === "user-management" && "User Management"}
                        {activeMenu === "asset-requirement" && "Asset Requirement"}
                        {activeMenu === "asset-list" && "Asset List"}
                        {activeMenu === "auto-discovery" && "Auto Discovery"}
                        {activeMenu === "auditing" && "Auditing"}
                        {activeMenu === "hardening" && "Hardening"}
                        {activeMenu === "logs" && "Logs"}
                    </h1>
                    <div className="header-right">
                        <div className="date-time">
                            <div className="current-date">{currentDate}</div>
                            <div className="current-time">
<img src={"/icons/watch.png"} style={{width:"15px", height:"15px",margin:"15px 8px -1px 1px"}} alt={"logo"} />
                                {currentTimeString}</div>
                        </div>
                    </div>
                </header>

                {/* Conditional Content Based on Active Menu */}
                {activeMenu === "dashboard" && (
                    <div className="dashboard-cards">
                        <div className="stat-card">
                            <div className="card-icon">💻</div>
                            <div className="card-number">1</div>
                            <div className="card-title">Total Assets</div>
                        </div>

                        <div className="stat-card">
                            <div className="card-icon">✅</div>
                            <div className="card-number">1</div>
                            <div className="card-title">Active Assets</div>
                        </div>

                        <div className="stat-card">
                            <div className="card-icon">⚠️</div>
                            <div className="card-number">0</div>
                            <div className="card-title">Pending Issues</div>
                        </div>

                        <div className="stat-card">
                            <div className="card-icon">👥</div>
                            <div className="card-number">1</div>
                            <div className="card-title">Total Users</div>
                        </div>
                    </div>
                )}

                {activeMenu === "user-management" && <UserManagement />}

                {activeMenu === "asset-list" && <AssetList />}


                {activeMenu === "asset-requirement" && <AssetRequirement />}

                {activeMenu === "auto-discovery" && <AutoDiscovery />}

                {activeMenu === "auditing" && (
                    <div className="placeholder-content">
                        <h3>Auditing</h3>
                        <p>Coming soon...</p>
                    </div>
                )}

                {activeMenu === "hardening" && (
                    <div className="placeholder-content">
                        <h3>Hardening</h3>
                        <p>Coming soon...</p>
                    </div>
                )}

                {activeMenu === "logs" && (
                    <div className="placeholder-content">
                        <h3>Logs</h3>
                        <p>Coming soon...</p>
                    </div>
                )}
            </main>
        </div>
    );
};