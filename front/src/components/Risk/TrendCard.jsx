import React from "react";
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    CartesianGrid,
} from "recharts";
import { TREND_BAR_COLOR } from "./riskConstants";
import { t, n } from "../../i18n";

/** "2026-06" -> "Jun" — the Figma axis shows short month names. */
const MONTH_LABELS = [
    t("Jan"), t("Feb"), t("Mar"), t("Apr"), t("May"), t("Jun"),
    t("Jul"), t("Aug"), t("Sep"), t("Oct"), t("Nov"), t("Dec"),
];

const toLabel = (period) => {
    const [, month] = String(period).split("-");
    const index = Number(month) - 1;
    return MONTH_LABELS[index] || period;
};

/**
 * Monthly average risk score (GET /api/risk/trend).
 * Figma: 18px bars, rx 2, #29354E.
 */
export const TrendCard = ({ points, message }) => {
    const data = (points || []).map((point) => ({
        label: toLabel(point.period),
        period: point.period,
        score: point.average_score,
        assets: point.asset_count,
    }));

    return (
        <section className="risk-card risk-chart-card">
            <h3 className="risk-card-title">{t("Average Risk Score Trend")}</h3>
            <div className="risk-chart-body">
                {data.length === 0 ? (
                    <p className="risk-chart-empty">
                        {message || t("No historical data yet.")}
                    </p>
                ) : (
                    <ResponsiveContainer width="100%" height={260}>
                        <BarChart
                            data={data}
                            margin={{ top: 16, right: 16, bottom: 8, left: 0 }}
                        >
                            <CartesianGrid stroke="#EEF0F4" vertical={false} />
                            <XAxis
                                dataKey="label"
                                tick={{ fontSize: 11, fill: "#6C7A93" }}
                                axisLine={false}
                                tickLine={false}
                            />
                            <YAxis
                                domain={[0, 100]}
                                tickFormatter={(v) => n(v)}
                                tick={{ fontSize: 11, fill: "#6C7A93" }}
                                axisLine={false}
                                tickLine={false}
                                width={36}
                            />
                            <Tooltip
                                formatter={(value, _name, entry) => [
                                    t("{{score}} · {{count}} assets", { score: value, count: entry.payload.assets }),
                                    t("Avg score"),
                                ]}
                                labelFormatter={(_label, payload) =>
                                    payload?.[0]?.payload.period || ""
                                }
                            />
                            <Bar
                                dataKey="score"
                                fill={TREND_BAR_COLOR}
                                barSize={18}
                                radius={[2, 2, 0, 0]}
                            />
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </div>
        </section>
    );
};

export default TrendCard;
