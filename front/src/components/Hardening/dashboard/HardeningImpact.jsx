import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

/**
 * "Hardening Impact": before/after donuts of critical & high findings.
 * Figma: two r=100 rings with a r=45 hole, split by a vertical divider.
 *
 * Backed by /api/hardening/dashboard/impact. There is no stored baseline, so
 * "before" is the set of critical/high findings hardening was applied to and
 * "after" is that set minus the ones a hardening action fixed — both derived
 * from hardening_actions.audit_result_id.
 */
const COLORS = ["#CC000B", "#F42535"];

/* Colour by severity, not by position — an "after" ring whose Critical slice
   has dropped to zero must not repaint High in Critical's colour. */
const colorFor = (label, i) =>
    ({ Critical: COLORS[0], High: COLORS[1] }[label] || COLORS[i % COLORS.length]);

const Donut = ({ title, data }) => {
    const slices = (data || []).filter((d) => d.value > 0);
    const total = slices.reduce((sum, d) => sum + d.value, 0);
    return (
        <div className="hd-impact-side">
            <h4 className="hd-impact-subtitle">{title}</h4>
            {slices.length > 0 ? (
                <>
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie
                                data={slices}
                                dataKey="value"
                                nameKey="label"
                                cx="50%"
                                cy="50%"
                                innerRadius={45}
                                outerRadius={100}
                                paddingAngle={1}
                            >
                                {slices.map((entry, i) => (
                                    <Cell key={entry.label} fill={colorFor(entry.label, i)} />
                                ))}
                            </Pie>
                        </PieChart>
                    </ResponsiveContainer>
                    <p className="hd-impact-total">{total} findings</p>
                    <div className="hd-impact-legend">
                        {(data || []).map((entry, i) => (
                            <span key={entry.label}>
                                <i
                                    className="hd-dot"
                                    style={{ background: colorFor(entry.label, i) }}
                                />
                                {entry.label}: {entry.value}
                            </span>
                        ))}
                    </div>
                </>
            ) : (
                /* An empty "after" ring is the good outcome, not missing data. */
                <p className="hd-empty">
                    {data ? "No critical or high findings remaining" : "No data"}
                </p>
            )}
        </div>
    );
};

export const HardeningImpact = ({
    before, after, resolved, reductionPercent, message,
}) => (
    <div className="hd-impact">
        <Donut title="Before Hardening" data={before} />
        <Donut title="After Hardening" data={after} />
        {message ? (
            <p className="hd-impact-note">{message}</p>
        ) : (
            resolved > 0 && (
                <p className="hd-impact-note">
                    {resolved} critical/high finding{resolved === 1 ? "" : "s"} resolved
                    by hardening ({reductionPercent}% reduction).
                </p>
            )
        )}
    </div>
);

export default HardeningImpact;
