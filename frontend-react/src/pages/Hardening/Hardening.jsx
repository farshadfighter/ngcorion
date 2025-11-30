/* ==========================================
   NGCORION - Hardening Page
   ========================================== */

import './Hardening.css';

const Hardening = () => {
  return (
    <div className="hardening-page">
      <div className="page-header">
        <h1 className="page-title">Hardening</h1>
      </div>
      <div className="card">
        <div className="placeholder-content">
          <svg viewBox="0 0 24 24" fill="currentColor" className="placeholder-icon">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
          </svg>
          <h3>System Hardening</h3>
          <p>Apply security hardening policies to your network assets.</p>
          <p className="coming-soon">Coming Soon</p>
        </div>
      </div>
    </div>
  );
};

export default Hardening;
