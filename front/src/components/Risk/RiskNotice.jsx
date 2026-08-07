import React from "react";

/** The rounded hint bar above the tabs (Figma: 1426x93, rx 30, #14213D text). */
export const RiskNotice = ({ children }) => (
    <div className="risk-notice">
        <i className="fa-solid fa-circle-exclamation" aria-hidden="true"></i>
        <span>{children}</span>
    </div>
);

export default RiskNotice;
