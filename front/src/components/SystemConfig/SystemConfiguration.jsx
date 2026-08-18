import React, { useState } from "react";

import { SECTIONS } from "./sections";
import "../../assets/SystemConfig.css";

/**
 * System Configuration landing page: one card per configurable subsystem,
 * each opening its own modal. Mirrors the Figma 3x2 grid.
 *
 * Every section maps to a pair of endpoints under /api/system — see sections.js
 * for the mapping, which is the single place the two stay in step.
 */
export const SystemConfiguration = () => {
    const [active, setActive] = useState(null);

    const ActiveModal = active?.modal;

    return (
        <div className="sc-page">
            <div className="sc-grid">
                {SECTIONS.map((section) => (
                    <button
                        key={section.key}
                        type="button"
                        className="sc-card"
                        onClick={() => setActive(section)}
                    >
                        <i className={`${section.icon} sc-card-icon`} aria-hidden="true" />
                        <span className="sc-card-title">{section.title}</span>
                        <span className="sc-card-hint">{section.hint}</span>
                    </button>
                ))}
            </div>

            {ActiveModal && <ActiveModal onClose={() => setActive(null)} />}
        </div>
    );
};

export default SystemConfiguration;
