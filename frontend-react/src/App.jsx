/* ==========================================
   NGCORION - App Component
   ========================================== */

import { Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import PrivateRoute from './components/common/PrivateRoute';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import AssetList from './pages/AssetList';
import AssetRequirement from './pages/AssetRequirement';
import AutoDiscovery from './pages/AutoDiscovery/AutoDiscovery';
import Auditing from './pages/Auditing';
import Hardening from './pages/Hardening';
import Logs from './pages/Logs';
import './App.css';


function App() {
  return (
    <div className="app">
      <Routes>
        {/* Public Route */}
        <Route path="/login" element={<Login />} />

        {/* Protected Routes */}
        <Route
          element={
            <PrivateRoute>
              <MainLayout />
            </PrivateRoute>
          }
        >
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/users" element={<Users />} />
          <Route path="/assets" element={<AssetList />} />
          <Route path="/asset-requirement" element={<AssetRequirement />} />
          <Route path="/auto-discovery" element={<AutoDiscovery />} />
          <Route path="/discovery" element={<AutoDiscovery />} />
          <Route path="/auditing" element={<Auditing />} />
          <Route path="/hardening" element={<Hardening />} />
          <Route path="/logs" element={<Logs />} />
        </Route>

        {/* Redirect */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </div>
  );
}

export default App;