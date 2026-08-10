import React from "react";

/** White panel with a centred title — the repeating container in the design. */
export const HardeningCard = ({ title, className = "", children }) => (
    <section className={`hd-card ${className}`}>
        <h3 className="hd-card-title">{title}</h3>
        {children}
    </section>
);

export default HardeningCard;
