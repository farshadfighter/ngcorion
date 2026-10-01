import React from "react";
import {
    LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer,
} from "recharts";

import { RiskLevelBadge } from "../RiskLevelBadge";
import { formatDate } from "../riskConstants";
import { t, uiLocale } from "../../../i18n";

/** trigger_type values written by risk_calculation_service.calculate(). */
const TRIGGER_LABELS = {
    asset_created: t("Asset created"),
    audit_completed: t("Audit completed"),
    hardening_verified: t("Hardening verified"),
    manual: t("Manual recalculation"),
    bulk_recalculation: t("Bulk recalculation"),
    port_scan_updated: t("Port scan updated"),
    port_updated: t("Ports changed"),
    profile_updated: t("Profile changed"),
    zone_updated: t("Zone changed"),
};

const triggerLabel = (reason) =>
    TRIGGER_LABELS[reason] || (reason ? reason.replace(/_/g, " ") : "—");

const shortDate = (value) => {
    if (!value) return "";
    const d = new Date(value);
    return Number.isNaN(d.getTime())
        ? ""
        : d.toLocaleDateString(uiLocale(),  { month: "short", day: "2-digit" });
};

/**
 * "Risk History": how this asset's score moved after each recalculation, and
 * which audit produced it.
 *
 * The client asked for a score per audit. Nothing stores one directly — the
 * score is always a single current value — but asset_risk_history writes a row
 * per calculation carrying audit_id and the trigger, so the audit-driven rows
 * are exactly the per-audit scores.
 */
export const RiskHistory = ({ history, isLoading, error }) => {
    if (isLoading) {
        return (
            <section className="ard-card">
                <h3 className="ard-card-title">{t("Risk History")}</h3>
                <p className="ard-empty">{t("Loading history…")}</p>
            </section>
        );
    }

    if (error) {
        return (
            <section className="ard-card">
                <h3 className="ard-card-title">{t("Risk History")}</h3>
                <p className="ard-empty">{error}</p>
            </section>
        );
    }

    if (!history || history.length === 0) {
        return (
            <section className="ard-card">
                <h3 className="ard-card-title">{t("Risk History")}</h3>
                <p className="ard-empty">
                    {t("No recalculations recorded for this asset yet.")}
                </p>
            </section>
        );
    }

    // The API returns newest first; a trend line has to read left-to-right.
    const chartData = [...history]
        .reverse()
        .map((h) => ({
            label: shortDate(h.calculated_at),
            score: h.risk_score,
            level: h.risk_level,
            reason: triggerLabel(h.reason),
        }));

    return (
        <section className="ard-card">
            <h3 className="ard-card-title">{t("Risk History")}</h3>

            {chartData.length > 1 && (
                <ResponsiveContainer width="100%" height={200}>
                    <LineChart
                        data={chartData}
                        margin={{ top: 12, right: 16, bottom: 4, left: 0 }}
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
                            width={36}
                            tick={{ fontSize: 11, fill: "#6C7A93" }}
                            axisLine={false}
                            tickLine={false}
                        />
                        <Tooltip
                            formatter={(value, _n, entry) => [
                                `${value} (${entry.payload.reason})`,
                                t("Risk score"),
                            ]}
                        />
                        <Line
                            type="monotone"
                            dataKey="score"
                            stroke="#14213D"
                            strokeWidth={2}
                            dot={{ r: 3, fill: "#14213D" }}
                        />
                    </LineChart>
                </ResponsiveContainer>
            )}

            <div className="ard-table-wrapper">
                <table className="ard-table">
                    <thead>
                        <tr>
                            <th>{t("Date")}</th>
                            <th>{t("Trigger")}</th>
                            <th>{t("Audit")}</th>
                            <th>{t("Score")}</th>
                            <th>{t("Level")}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {history.map((h) => (
                            <tr key={h.id}>
                                <td>{formatDate(h.calculated_at)}</td>
                                <td>{triggerLabel(h.reason)}</td>
                                <td>
                                    {h.audit_id ? (
                                        `#${h.audit_id}`
                                    ) : (
                                        <span className="risk-muted">—</span>
                                    )}
                                </td>
                                <td>
                                    {h.risk_score === null ||
                                    h.risk_score === undefined
                                        ? "-"
                                        : Math.round(h.risk_score)}
                                </td>
                                <td>
                                    <RiskLevelBadge level={h.risk_level} />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </section>
    );
};

export default RiskHistory;
