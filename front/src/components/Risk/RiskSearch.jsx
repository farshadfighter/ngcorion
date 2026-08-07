import React from "react";

/** Search box above the table (Figma: 285x35, rx 5). */
export const RiskSearch = ({ value, onChange, placeholder = "Search Asset" }) => (
    <div className="risk-search">
        <i className="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
        <input
            type="search"
            value={value}
            placeholder={placeholder}
            aria-label={placeholder}
            onChange={(e) => onChange(e.target.value)}
        />
    </div>
);

export default RiskSearch;
