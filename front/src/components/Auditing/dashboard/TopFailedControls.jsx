import React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { t, n } from "../../../i18n";

const COLORS = ["#4299e1", "#805ad5", "#ecc94b", "#48bb78", "#ed8936", "#e53e3e", "#38b2ac", "#a0aec0"];

/** "Top Failed Controls" donut — the checks failing most often. */
export const TopFailedControls = ({ items }) => {
    const data = (items || []).filter((i) => i.fail_count > 0);

    return (
        <div className="aud-card">
            <div className="aud-card-title">{t("Top Failed Controls")}</div>
            {data.length === 0 ? (
                <div className="aud-empty">{t("No failed controls recorded yet.")}</div>
            ) : (
                <>
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie
                                data={data}
                                dataKey="fail_count"
                                nameKey="check_number"
                                cx="50%"
                                cy="50%"
                                innerRadius={55}
                                outerRadius={95}
                                paddingAngle={1}
                            >
                                {data.map((entry, i) => (
                                    <Cell key={entry.check_number} fill={COLORS[i % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip
                                formatter={(v, _n, e) => [
                                    t("{{v}} failures on {{affected_assets}} assets", { v, affected_assets: e.payload.affected_assets }),
                                    e.payload.check_title || e.payload.check_number,
                                ]}
                            />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="aud-legend">
                        {data.map((entry, i) => (
                            <span
                                className="aud-legend-item"
                                key={entry.check_number}
                                title={entry.check_title || ""}
                            >
                                <i
                                    className="aud-legend-dot"
                                    style={{ background: COLORS[i % COLORS.length] }}
                                />
                                <bdi>{entry.check_number}</bdi>: <b>{n(entry.fail_count)}</b>
                            </span>
                        ))}
                    </div>
                </>
            )}
        </div>
    );
};

export default TopFailedControls;
