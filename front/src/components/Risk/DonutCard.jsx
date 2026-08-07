import React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

/**
 * Donut chart card with legend (Figma: 571x529 card, r=100 ring with a 45 hole).
 *
 * A lone "unclassified" slice counts as no data: a solid ring would imply the
 * field was populated when in fact the API never returned it.
 */
export const DonutCard = ({ title, data, colorFor, emptyMessage }) => {
    const isOnlyUnclassified = data.length === 1 && data[0].key === "unclassified";
    const hasData =
        data.length > 0 && data.some((d) => d.count > 0) && !isOnlyUnclassified;

    return (
        <section className="risk-card risk-chart-card">
            <h3 className="risk-card-title">{title}</h3>
            <div className="risk-chart-body">
                {hasData ? (
                    <ResponsiveContainer width="100%" height={240}>
                        <PieChart>
                            <Pie
                                data={data}
                                dataKey="count"
                                nameKey="label"
                                cx="50%"
                                cy="50%"
                                innerRadius={54}
                                outerRadius={120}
                                paddingAngle={1}
                            >
                                {data.map((entry) => (
                                    <Cell key={entry.key} fill={colorFor(entry, data)} />
                                ))}
                            </Pie>
                            <Tooltip formatter={(value, name) => [value, name]} />
                        </PieChart>
                    </ResponsiveContainer>
                ) : (
                    <p className="risk-chart-empty">{emptyMessage}</p>
                )}
            </div>
            {hasData && (
                <div className="risk-legend">
                    {data.map((entry) => (
                        <span className="risk-legend-item" key={entry.key}>
                            <span
                                className="risk-legend-swatch"
                                style={{ background: colorFor(entry, data) }}
                            />
                            {entry.label}:{" "}
                            <span className="risk-legend-count">{entry.count}</span>
                        </span>
                    ))}
                </div>
            )}
        </section>
    );
};

export default DonutCard;
