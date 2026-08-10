import React from "react";

/**
 * Labelled percentage bars — used by Coverage By Asset Type, Policy Compliance
 * and By Vendor, which share the same shape in the Figma design.
 */
export const ProgressList = ({ items, emptyMessage }) => {
    if (!items || items.length === 0) {
        return <p className="hd-empty">{emptyMessage}</p>;
    }

    return (
        <ul className="hd-progress-list">
            {items.map((item) => (
                <li className="hd-progress-item" key={item.name}>
                    <span className="hd-progress-label">{item.name}</span>
                    <span className="hd-progress-row">
                        <span className="hd-progress-track">
                            <span
                                className="hd-progress-fill"
                                style={{ width: `${Math.min(100, item.percent)}%` }}
                            />
                        </span>
                        <span className="hd-progress-value">{item.percent}%</span>
                    </span>
                </li>
            ))}
        </ul>
    );
};

export default ProgressList;
