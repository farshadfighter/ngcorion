import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer,
} from "recharts";

import { fetchHardeningDashboard } from "../../../store/hardeningDashboardSlice";
import { HardeningCard } from "./HardeningCard";
import { ProgressList } from "./ProgressList";
import { HardeningImpact } from "./HardeningImpact";
import "../../../assets/HardeningDashboard.css";

const BAR_COLOR = "#29354E";

const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const monthLabel = (period) => {
    const [, m] = String(period).split("-");
    return MONTHS[Number(m) - 1] || period;
};

const fmt = (v) => (typeof v === "number" ? v.toLocaleString("en-US") : v ?? "-");

const Stat = ({ label, value, suffix }) => (
    <div className="hd-stat">
        <span className="hd-stat-label">{label}</span>
        <span className="hd-stat-value">
            {value === null || value === undefined ? "—" : fmt(value)}
            {suffix}
        </span>
    </div>
);

export const HardeningDashboard = () => {
    const dispatch = useDispatch();
    const {
        overview, progress, coverage, vendors, compliance, activities,
        requiring, missing, impact, isLoading, error,
    } = useSelector((state) => state.hardeningDashboard);

    useEffect(() => {
        dispatch(fetchHardeningDashboard());
    }, [dispatch]);

    if (isLoading && !overview) {
        return <div className="hd-page"><p className="hd-state">Loading hardening data…</p></div>;
    }

    if (error) {
        return (
            <div className="hd-page">
                <p className="hd-state hd-state-error">
                    Failed to load hardening dashboard: {error}
                </p>
            </div>
        );
    }

    const auto = overview?.automation;
    const trend = (progress?.points || []).map((p) => ({
        label: monthLabel(p.period),
        period: p.period,
        rate: p.success_rate,
        total: p.total,
    }));

    return (
        <div className="hd-page">
            <div className="hd-grid">
                {/* ── Overview ── */}
                <HardeningCard title="Hardening Overview" className="hd-card-overview">
                    <div className="hd-stat-grid">
                        <Stat label="Hardening Score" value={overview?.hardening_score} suffix="%" />
                        <Stat label="Hardened Assets" value={overview?.hardened_assets} />
                        <Stat label="Non-Hardened Assets" value={overview?.non_hardened_assets} />
                        <Stat label="Applied Policies" value={overview?.applied_policies} />
                        <Stat label="Failed Hardening Actions" value={overview?.failed_actions} />
                        <Stat label="Pending Actions" value={overview?.pending_actions} />
                    </div>
                </HardeningCard>

                {/* ── Progress ── */}
                <HardeningCard title="Hardening Progress" className="hd-card-progress">
                    {trend.length === 0 ? (
                        <p className="hd-empty">
                            {progress?.message || "No hardening activity recorded yet."}
                        </p>
                    ) : (
                        <ResponsiveContainer width="100%" height={240}>
                            <BarChart data={trend} margin={{ top: 16, right: 12, bottom: 4, left: 0 }}>
                                <CartesianGrid stroke="#EEF0F4" vertical={false} />
                                <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#6C7A93" }}
                                       axisLine={false} tickLine={false} />
                                <YAxis domain={[0, 100]} width={36}
                                       tick={{ fontSize: 11, fill: "#6C7A93" }}
                                       axisLine={false} tickLine={false} />
                                <Tooltip
                                    formatter={(v, _n, e) => [`${v}% (${e.payload.total} actions)`, "Success rate"]}
                                    labelFormatter={(_l, p) => p?.[0]?.payload.period || ""}
                                />
                                <Bar dataKey="rate" fill={BAR_COLOR} barSize={18} radius={[2, 2, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </HardeningCard>

                {/* ── Coverage ── */}
                <HardeningCard title="Hardening Coverage By Asset Type" className="hd-card-centered">
                    <ProgressList
                        items={coverage?.items}
                        emptyMessage="No assets recorded yet."
                    />
                </HardeningCard>

                {/* ── Policy compliance ── */}
                <HardeningCard title="Hardening Policy Compliance">
                    <ProgressList
                        items={(compliance?.items || []).map((i) => ({ ...i, name: i.level }))}
                        emptyMessage="No hardening actions linked to audit levels yet."
                    />
                </HardeningCard>

                {/* ── By vendor ── */}
                <HardeningCard title="Hardening By Vendor">
                    <ProgressList
                        items={vendors?.items}
                        emptyMessage="No hardening actions recorded yet."
                    />
                </HardeningCard>

                {/* ── Recent activities ── */}
                <HardeningCard title="Recent Hardening Activities" className="hd-card-centered">
                    <div className="hd-table-wrapper">
                        <table className="hd-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Asset</th>
                                    <th>Control</th>
                                    <th>Action</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(activities?.items || []).length === 0 && (
                                    <tr>
                                        <td colSpan={5} className="hd-table-empty">
                                            No hardening activity yet.
                                        </td>
                                    </tr>
                                )}
                                {(activities?.items || []).map((a) => (
                                    <tr key={a.id}>
                                        <td>
                                            {a.created_at
                                                ? new Date(a.created_at).toLocaleString("en-US", {
                                                      month: "short", day: "2-digit",
                                                      hour: "2-digit", minute: "2-digit", hour12: false,
                                                  })
                                                : "-"}
                                        </td>
                                        <td>{a.asset_name || "-"}</td>
                                        <td>{a.check_number || "-"}</td>
                                        <td className="hd-cell-wide">{a.check_title || "-"}</td>
                                        <td>
                                            <span className={`hd-status hd-status-${a.status}`}>
                                                {a.status}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </HardeningCard>

                {/* ── Assets requiring hardening / top missing controls ── */}
                <HardeningCard title="Assets Requiring Hardening">
                    <div className="hd-table-wrapper">
                        <table className="hd-table">
                            <thead>
                                <tr>
                                    <th>Asset</th>
                                    <th>Risk</th>
                                    <th>Active Findings</th>
                                    <th>Fixed</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(requiring?.items || []).length === 0 && (
                                    <tr>
                                        <td colSpan={4} className="hd-table-empty">
                                            No assets with unresolved findings.
                                        </td>
                                    </tr>
                                )}
                                {(requiring?.items || []).map((a) => (
                                    <tr key={a.asset_id}>
                                        <td>{a.asset_name || "-"}</td>
                                        <td>
                                            {a.risk_level ? (
                                                <span className={`hd-risk hd-risk-${a.risk_level}`}>
                                                    {a.risk_level.replace("_", " ")}
                                                </span>
                                            ) : (
                                                <span className="hd-muted">—</span>
                                            )}
                                        </td>
                                        <td>{a.active_findings_count ?? "-"}</td>
                                        <td>{a.resolved_by_hardening ?? "-"}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </HardeningCard>

                <HardeningCard title="Top Missing Hardening Controls">
                    <div className="hd-table-wrapper">
                        <table className="hd-table">
                            <thead>
                                <tr>
                                    <th>Control</th>
                                    <th>Assets</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(missing?.items || []).length === 0 && (
                                    <tr>
                                        <td colSpan={2} className="hd-table-empty">
                                            No outstanding controls.
                                        </td>
                                    </tr>
                                )}
                                {(missing?.items || []).map((c) => (
                                    <tr key={c.check_number}>
                                        <td className="hd-cell-wide">
                                            {c.check_number}
                                            {c.check_title ? ` — ${c.check_title}` : ""}
                                        </td>
                                        <td>{c.affected_assets}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </HardeningCard>

                {/* ── Automation success ── */}
                <HardeningCard title="Automation Success Rate" className="hd-card-centered">
                    <div className="hd-stat-grid hd-stat-grid-2">
                        <Stat label="Executed Tasks" value={auto?.executed_tasks} />
                        <Stat label="Success Rate" value={auto?.success_rate} suffix="%" />
                    </div>
                    {auto && auto.executed_tasks > 0 && (
                        <>
                            <div className="hd-split-bar">
                                <span
                                    className="hd-split-success"
                                    style={{ width: `${auto.success_rate}%` }}
                                />
                                <span
                                    className="hd-split-failed"
                                    style={{ width: `${100 - auto.success_rate}%` }}
                                />
                            </div>
                            <div className="hd-split-legend">
                                <span><i className="hd-dot hd-dot-success" /> Success: {fmt(auto.success)}</span>
                                <span><i className="hd-dot hd-dot-failed" /> Failed: {fmt(auto.failed)}</span>
                            </div>
                        </>
                    )}
                </HardeningCard>

                {/* ── Hardening impact ── */}
                <HardeningCard title="Hardening Impact" className="hd-card-wide">
                    <HardeningImpact
                        before={impact?.before}
                        after={impact?.after}
                        resolved={impact?.resolved}
                        reductionPercent={impact?.reduction_percent}
                        message={impact?.message}
                    />
                </HardeningCard>
            </div>
        </div>
    );
};

export default HardeningDashboard;
