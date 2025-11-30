/* ==========================================
   NGCORION - Tabs Component
   ========================================== */

import './Tabs.css';

const Tabs = ({ tabs, activeTab, onChange }) => {
  return (
    <div className="tabs">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          className={`tab ${activeTab === tab.key ? 'tab-active' : ''}`}
          onClick={() => onChange(tab.key)}
        >
          {tab.icon && <span className="tab-icon">{tab.icon}</span>}
          {tab.label}
        </button>
      ))}
    </div>
  );
};

export default Tabs;
