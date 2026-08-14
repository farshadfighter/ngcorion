import React from "react";
import {
    LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer,
} from "recharts";

import { RiskLevelBadge } from "../RiskLevelBadge";
import { formatDate } from "../riskConstants";

/** trigger_type values written by risk_calculation_service.calculate(). */
const TRIGGER_LABELS = {
    asset_created: "Asset created",
    audit_completed: "Audit completed",
    hardening_verified: "Hardening verified",
    manual: "Manual recalculation",
    bulk_recalculation: "Bulk recalculation",
    port_scan_updated: "Port scan updated",
    port_updated: "Ports changed",
    profile_updated: "Profile changed",
    zone_updated: "Zone changed",
};

const triggerLabel = (reason) =>
    TRIGGER_LABELS[reason] || (reason ? reason.replace(/_/g, " ") : "—");

const shortDate = (value) => {
    if (!value) return "";
    const d = new Date(value);
    return Number.isNaN(d.getTime())
        ? ""
        : d.toLocaleDateString("en-US", { month: "short", day: "2-digit" });
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
                <h3 className="ard-card-title">Risk History</h3>
                <p className="ard-empty">Loading history…</p>
            </section>
        );
    }

    if (error) {
        return (
            <section className="ard-card">
                <h3 className="ard-card-title">Risk History</h3>
                <p className="ard-empty">{error}</p>
            </section>
        );
    }

    if (!history || history.length === 0) {
        return (
            <section className="ard-card">
                <h3 className="ard-card-title">Risk History</h3>
                <p className="ard-empty">
                    No recalculations recorded for this asset yet.
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
            <h3 className="ard-card-title">Risk History</h3>

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
                                "Risk score",
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
                            <th>Date</th>
                            <th>Trigger</th>
                            <th>Audit</th>
                            <th>Score</th>
                            <th>Level</th>
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
