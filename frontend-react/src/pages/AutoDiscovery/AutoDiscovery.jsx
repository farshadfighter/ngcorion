/* ==========================================
   NGCORION - Auto Discovery Page
   ========================================== */

import './AutoDiscovery.css';

const AutoDiscovery = () => {
  return (
    <div className="auto-discovery-page">
      <div className="page-header">
        <h1 className="page-title">Auto Discovery</h1>
      </div>
      <div className="card">
        <div className="placeholder-content">
          <svg viewBox="0 0 24 24" fill="currentColor" className="placeholder-icon">
            <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
          </svg>
          <h3>Network Auto Discovery</h3>
          <p>Automatically scan and discover network assets using nmap.</p>
          <p className="coming-soon">Coming Soon</p>
        </div>
      </div>
    </div>
  );
};

export default AutoDiscovery;
