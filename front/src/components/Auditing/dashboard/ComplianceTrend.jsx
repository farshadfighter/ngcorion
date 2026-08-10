import React from "react";
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer,
} from "recharts";

const BAR_COLOR = "#1e3a5f";

const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

/* "2026-02-14" -> "2/14" (daily view), "2026-02" -> "Feb" (monthly fallback). */
const periodLabel = (period) => {
    const parts = String(period).split("-");
    if (parts.length === 3) return `${Number(parts[1])}/${Number(parts[2])}`;
    return MONTHS[Number(parts[1]) - 1] || period;
};

/** "Compliance Trend" — monthly average compliance percentage. */
export const ComplianceTrend = ({ points, message }) => {
    const data = (points || []).map((p) => ({
        label: periodLabel(p.period),
        period: p.period,
        compliance: p.average_compliance,
        sessions: p.session_count,
    }));

    return (
        <div className="aud-card">
            <div className="aud-card-title">Compliance Trend</div>
            {data.length === 0 ? (
                <div className="aud-empty">{message || "No completed audits yet."}</div>
            ) : (
                <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={data} margin={{ top: 16, right: 12, bottom: 4, left: 0 }}>
                        <CartesianGrid stroke="#eef0f4" vertical={false} />
                        <XAxis
                            dataKey="label"
                            tick={{ fontSize: 11, fill: "#6c7a93" }}
                            axisLine={false}
                            tickLine={false}
                        />
                        <YAxis
                            domain={[0, 100]}
                            width={36}
                            tick={{ fontSize: 11, fill: "#6c7a93" }}
                            axisLine={false}
                            tickLine={false}
                        />
                        <Tooltip
                            formatter={(v, _n, e) => [
                                `${v}% (${e.payload.sessions} audits)`,
                                "Avg compliance",
                            ]}
                            labelFormatter={(_l, p) => p?.[0]?.payload.period || ""}
                        />
                        <Bar dataKey="compliance" fill={BAR_COLOR} barSize={18} radius={[2, 2, 0, 0]} />
                    </BarChart>
                </ResponsiveContainer>
            )}
        </div>
    );
};

export default ComplianceTrend;
