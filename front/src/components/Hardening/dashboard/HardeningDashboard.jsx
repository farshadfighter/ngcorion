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
import { t, uiLocale, n } from "../../../i18n";
import { ReportShortcut } from "../../Reports/ReportShortcut.jsx";

const BAR_COLOR = "#29354E";

const MONTHS = [t("Jan"),t("Feb"),t("Mar"),t("Apr"),t("May"),t("Jun"),t("Jul"),t("Aug"),t("Sep"),t("Oct"),t("Nov"),t("Dec")];
const monthLabel = (period) => {
    const [, m] = String(period).split("-");
    return MONTHS[Number(m) - 1] || period;
};

const fmt = (v) => (typeof v === "number" ? v.toLocaleString(uiLocale()) : v ?? "-");

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
        return <div className="hd-page"><p className="hd-state">{t("Loading hardening data…")}</p></div>;
    }

    if (error) {
        return (
            <div className="hd-page">
                <p className="hd-state hd-state-error">
                    {t("Failed to load hardening dashboard: {{error}}", { error })}
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
            <div className="rep-shortcut-row"><ReportShortcut template="hardening_changes" className="bkm-btn bkm-btn-sm" /></div>
            <div className="hd-grid">
                {/* ── Overview ── */}
                <HardeningCard title={t("Hardening Overview")} className="hd-card-overview">
                    <div className="hd-stat-grid">
                        <Stat label={t("Hardening Score")} value={overview?.hardening_score} suffix="%" />
                        <Stat label={t("Hardened Assets")} value={overview?.hardened_assets} />
                        <Stat label={t("Non-Hardened Assets")} value={overview?.non_hardened_assets} />
                        <Stat label={t("Applied Policies")} value={overview?.applied_policies} />
                        <Stat label={t("Failed Hardening Actions")} value={overview?.failed_actions} />
                        <Stat label={t("Pending Actions")} value={overview?.pending_actions} />
                    </div>
                </HardeningCard>

                {/* ── Progress ── */}
                <HardeningCard title={t("Hardening Progress")} className="hd-card-progress">
                    {trend.length === 0 ? (
                        <p className="hd-empty">
                            {progress?.message || t("No hardening activity recorded yet.")}
                        </p>
                    ) : (
                        <ResponsiveContainer width="100%" height={240}>
                            <BarChart data={trend} margin={{ top: 16, right: 12, bottom: 4, left: 0 }}>
                                <CartesianGrid stroke="#EEF0F4" vertical={false} />
                                <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#6C7A93" }}
                                       axisLine={false} tickLine={false} />
                                <YAxis domain={[0, 100]} width={36} tickFormatter={(v) => n(v)}
                                       tick={{ fontSize: 11, fill: "#6C7A93" }}
                                       axisLine={false} tickLine={false} />
                                <Tooltip
                                    formatter={(v, _n, e) => [t("{{pct}}% · {{count}} actions", { pct: v, count: e.payload.total }), t("Success rate")]}
                                    labelFormatter={(_l, p) => p?.[0]?.payload.period || ""}
                                />
                                <Bar dataKey="rate" fill={BAR_COLOR} barSize={18} radius={[2, 2, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </HardeningCard>

                {/* ── Coverage ── */}
                <HardeningCard title={t("Hardening Coverage By Asset Type")} className="hd-card-centered">
                    <ProgressList
                        items={coverage?.items}
                        emptyMessage={t("No assets recorded yet.")}
                    />
                </HardeningCard>

                {/* ── Policy compliance ── */}
                <HardeningCard title={t("Hardening Policy Compliance")}>
                    <ProgressList
                        items={(compliance?.items || []).map((i) => ({ ...i, name: i.level }))}
                        emptyMessage={t("No hardening actions linked to audit levels yet.")}
                    />
                </HardeningCard>

                {/* ── By vendor ── */}
                <HardeningCard title={t("Hardening By Vendor")}>
                    <ProgressList
                        items={vendors?.items}
                        emptyMessage={t("No hardening actions recorded yet.")}
                    />
                </HardeningCard>

                {/* ── Recent activities ── */}
                <HardeningCard title={t("Recent Hardening Activities")} className="hd-card-centered">
                    <div className="hd-table-wrapper">
                        <table className="hd-table">
                            <thead>
                                <tr>
                                    <th>{t("Time")}</th>
                                    <th>{t("Asset")}</th>
                                    <th>{t("Control")}</th>
                                    <th>{t("Action")}</th>
                                    <th>{t("Status")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(activities?.items || []).length === 0 && (
                                    <tr>
                                        <td colSpan={5} className="hd-table-empty">
                                            {t("No hardening activity yet.")}
                                        </td>
                                    </tr>
                                )}
                                {(activities?.items || []).map((a) => (
                                    <tr key={a.id}>
                                        <td>
                                            {a.created_at
                                                ? new Date(a.created_at).toLocaleString(uiLocale(),  {
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
                <HardeningCard title={t("Assets Requiring Hardening")}>
                    <div className="hd-table-wrapper">
                        <table className="hd-table">
                            <thead>
                                <tr>
                                    <th>{t("Asset")}</th>
                                    <th>{t("Risk")}</th>
                                    <th>{t("Active Findings")}</th>
                                    <th>{t("Fixed")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(requiring?.items || []).length === 0 && (
                                    <tr>
                                        <td colSpan={4} className="hd-table-empty">
                                            {t("No assets with unresolved findings.")}
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
                                        <td>{n(a.active_findings_count ?? "-")}</td>
                                        <td>{n(a.resolved_by_hardening ?? "-")}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </HardeningCard>

                <HardeningCard title={t("Top Missing Hardening Controls")}>
                    <div className="hd-table-wrapper">
                        <table className="hd-table">
                            <thead>
                                <tr>
                                    <th>{t("Control")}</th>
                                    <th>{t("Assets")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(missing?.items || []).length === 0 && (
                                    <tr>
                                        <td colSpan={2} className="hd-table-empty">
                                            {t("No outstanding controls.")}
                                        </td>
                                    </tr>
                                )}
                                {(missing?.items || []).map((c) => (
                                    <tr key={c.check_number}>
                                        <td className="hd-cell-wide">
                                            {c.check_number}
                                            {c.check_title ? ` — ${c.check_title}` : ""}
                                        </td>
                                        <td>{n(c.affected_assets)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </HardeningCard>

                {/* ── Automation success ── */}
                <HardeningCard title={t("Automation Success Rate")} className="hd-card-centered">
                    <div className="hd-stat-grid hd-stat-grid-2">
                        <Stat label={t("Executed Tasks")} value={auto?.executed_tasks} />
                        <Stat label={t("Success Rate")} value={auto?.success_rate} suffix="%" />
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
                                <span><i className="hd-dot hd-dot-success" /> {" "}{t("Success: {{success}}", { success: fmt(auto.success) })}</span>
                                <span><i className="hd-dot hd-dot-failed" /> {" "}{t("Failed: {{failed}}", { failed: fmt(auto.failed) })}</span>
                            </div>
                        </>
                    )}
                </HardeningCard>

                {/* ── Hardening impact ── */}
                <HardeningCard title={t("Hardening Impact")} className="hd-card-wide">
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
