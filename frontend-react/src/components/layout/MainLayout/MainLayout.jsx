/* ==========================================
   NGCORION - MainLayout Component
   ========================================== */

import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Header from '../Header';
import Sidebar from '../Sidebar';
import './MainLayout.css';

const MainLayout = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  return (
    <div className={`layout ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <Sidebar collapsed={sidebarCollapsed} />
      <Header onToggleSidebar={toggleSidebar} />
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
};

export default MainLayout;
