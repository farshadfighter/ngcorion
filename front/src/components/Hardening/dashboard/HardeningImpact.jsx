import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

/**
 * "Hardening Impact": before/after donuts of critical & high findings.
 * Figma: two r=100 rings with a r=45 hole, split by a vertical divider.
 *
 * No endpoint backs this yet — nothing records the pre-hardening baseline, the
 * same gap the risk module has. The card renders its frame and an explanatory
 * message so the layout matches the design and the reason is visible.
 */
const COLORS = ["#CC000B", "#F42535"];

const Donut = ({ title, data }) => {
    const hasData = data && data.some((d) => d.value > 0);
    return (
        <div className="hd-impact-side">
            <h4 className="hd-impact-subtitle">{title}</h4>
            {hasData ? (
                <>
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie
                                data={data}
                                dataKey="value"
                                nameKey="label"
                                cx="50%"
                                cy="50%"
                                innerRadius={45}
                                outerRadius={100}
                                paddingAngle={1}
                            >
                                {data.map((entry, i) => (
                                    <Cell key={entry.label} fill={COLORS[i % COLORS.length]} />
                                ))}
                            </Pie>
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="hd-impact-legend">
                        {data.map((entry, i) => (
                            <span key={entry.label}>
                                <i
                                    className="hd-dot"
                                    style={{ background: COLORS[i % COLORS.length] }}
                                />
                                {entry.label}: {entry.value}
                            </span>
                        ))}
                    </div>
                </>
            ) : (
                <p className="hd-empty">No data</p>
            )}
        </div>
    );
};

export const HardeningImpact = ({ before, after, message }) => (
    <div className="hd-impact">
        <Donut title="Before Hardening" data={before} />
        <Donut title="After Hardening" data={after} />
        {message && <p className="hd-impact-note">{message}</p>}
    </div>
);

export default HardeningImpact;
