import React from "react";

/**
 * Underlined tab strip (Figma: 0.3-opacity rule with a 2px #14213D marker
 * under the active tab).
 */
export const RiskTabs = ({ tabs, active, onChange }) => (
    <div className="risk-tabs" role="tablist">
        {tabs.map((tab) => (
            <button
                key={tab.key}
                type="button"
                role="tab"
                aria-selected={active === tab.key}
                className={`risk-tab ${active === tab.key ? "is-active" : ""}`}
                onClick={() => onChange(tab.key)}
            >
                {tab.label}
            </button>
        ))}
    </div>
);

export default RiskTabs;
