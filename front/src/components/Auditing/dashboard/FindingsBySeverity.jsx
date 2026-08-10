import React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

/** Same severity palette the result table and audit dashboard already use. */
const SEVERITY_COLORS = {
    critical: "#e53e3e",
    high: "#ed8936",
    medium: "#ecc94b",
    low: "#48bb78",
    info: "#4299e1",
    unspecified: "#a0aec0",
};

const label = (s) => s.charAt(0).toUpperCase() + s.slice(1);

/** "Findings By Severity" donut — failed checks grouped by severity. */
export const FindingsBySeverity = ({ items }) => {
    const data = (items || []).filter((i) => i.count > 0);

    return (
        <div className="aud-card">
            <div className="aud-card-title">Findings By Severity</div>
            {data.length === 0 ? (
                <div className="aud-empty">No failed checks recorded yet.</div>
            ) : (
                <>
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie
                                data={data}
                                dataKey="count"
                                nameKey="severity"
                                cx="50%"
                                cy="50%"
                                innerRadius={55}
                                outerRadius={95}
                                paddingAngle={1}
                            >
                                {data.map((entry) => (
                                    <Cell
                                        key={entry.severity}
                                        fill={SEVERITY_COLORS[entry.severity] || SEVERITY_COLORS.unspecified}
                                    />
                                ))}
                            </Pie>
                            <Tooltip formatter={(v, n) => [v, label(String(n))]} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="aud-legend">
                        {data.map((entry) => (
                            <span className="aud-legend-item" key={entry.severity}>
                                <i
                                    className="aud-legend-dot"
                                    style={{
                                        background:
                                            SEVERITY_COLORS[entry.severity] ||
                                            SEVERITY_COLORS.unspecified,
                                    }}
                                />
                                {label(entry.severity)}: <b>{entry.count}</b>
                            </span>
                        ))}
                    </div>
                </>
            )}
        </div>
    );
};

export default FindingsBySeverity;
