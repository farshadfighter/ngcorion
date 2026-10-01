import React from "react";
import { t } from "../../i18n";

/** Search box above the table (Figma: 285x35, rx 5). */
export const RiskSearch = ({ value, onChange, placeholder = t("Search Asset") }) => (
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
