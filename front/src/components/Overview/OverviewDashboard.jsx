import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";

import { fetchOverviewDashboard } from "../../store/overviewDashboardSlice";
import {
    headlineMetrics,
    moduleCards,
    complianceScore,
    hardeningScore,
} from "./overviewMetrics";
import "../../assets/OverviewDashboard.css";

const fmt = (value) =>
    typeof value === "number" ? value.toLocaleString("en-US") : value;

/** One of the six tiles across the top. */
const MetricCard = ({ metric }) => (
    <div className="ov-metric">
        <span className="ov-metric-label">{metric.label}</span>
        {metric.pending ? (
            <span className="ov-metric-pending" title="Waiting on a backend endpoint">
                —
            </span>
        ) : (
            <span className="ov-metric-value">
                {metric.value === null || metric.value === undefined
                    ? "—"
                    : fmt(metric.value)}
                {metric.value !== null && metric.value !== undefined && metric.suffix
                    ? metric.suffix
                    : ""}
            </span>
        )}
    </div>
);

/** One of the four module tiles; the whole card is the link to its screen. */
const ModuleCard = ({ card, onOpen }) => (
    <button type="button" className="ov-module" onClick={() => onOpen(card.to)}>
        <span className="ov-module-hint">
            <i className="fa-solid fa-circle-info" aria-hidden="true" /> click on
            to see more information
        </span>
        <span className="ov-module-body">
            <span className="ov-module-title">{card.title}</span>
            <span className="ov-module-value">
                {card.value === null || card.value === undefined ? (
                    "—"
                ) : (
                    <>
                        {fmt(card.value)}
                        {card.suffix || ""} {card.unit}
                    </>
                )}
            </span>
        </span>
    </button>
);

/** Two percentages side by side, each with its own bar. */
const ComplianceVsHardening = ({ compliance, hardening }) => (
    <section className="ov-card ov-card-medium ov-compare">
        <h3 className="ov-card-title">Compliance vs Hardening</h3>
        <div className="ov-compare-heads">
            <div className="ov-compare-head">
                <span className="ov-compare-label">Compliance</span>
                <span className="ov-compare-value">
                    {compliance === null ? "—" : `${compliance}%`}
                </span>
            </div>
            <div className="ov-compare-head">
                <span className="ov-compare-label">Hardening</span>
                <span className="ov-compare-value">
                    {hardening === null ? "—" : `${hardening}%`}
                </span>
            </div>
        </div>
        <div className="ov-compare-bars">
            <div className="ov-bar-row">
                <span className="ov-bar-track">
                    <span
                        className="ov-bar-fill ov-bar-compliance"
                        style={{ width: `${Math.min(100, compliance ?? 0)}%` }}
                    />
                </span>
                <span className="ov-bar-legend">
                    <i className="ov-dot ov-dot-compliance" /> Compliance:{" "}
                    {compliance === null ? "—" : `${compliance}%`}
                </span>
            </div>
            <div className="ov-bar-row">
                <span className="ov-bar-track">
                    <span
                        className="ov-bar-fill ov-bar-hardening"
                        style={{ width: `${Math.min(100, hardening ?? 0)}%` }}
                    />
                </span>
                <span className="ov-bar-legend">
                    <i className="ov-dot ov-dot-hardening" /> Hardening:{" "}
                    {hardening === null ? "—" : `${hardening}%`}
                </span>
            </div>
        </div>
    </section>
);

const dash = (value) =>
    value === null || value === undefined || value === "" ? "-" : value;

/** "Top 10 Risky Assets" — the highest-scoring assets, newest calculation. */
const TopRiskyAssets = ({ items }) => (
    <section className="ov-card ov-card-wide">
        <h3 className="ov-card-title">Top 10 Risky Assets</h3>
        <div className="ov-table-wrapper">
            <table className="ov-table">
                <thead>
                    <tr>
                        <th>Number</th>
                        <th>Asset Name</th>
                        <th>Hostname</th>
                        <th>Type</th>
                        <th>Zone</th>
                        <th>Manufacturer</th>
                        <th>Model</th>
                    </tr>
                </thead>
                <tbody>
                    {items.length === 0 && (
                        <tr>
                            <td colSpan={7} className="ov-table-empty">
                                No assets have a risk score yet.
                            </td>
                        </tr>
                    )}
                    {items.map((row, i) => (
                        <tr key={row.asset_id}>
                            <td>{row.rank ?? i + 1}</td>
                            <td>{dash(row.asset_name)}</td>
                            <td>{dash(row.hostname)}</td>
                            <td>{dash(row.asset_type)}</td>
                            <td>{dash(row.zone_name)}</td>
                            <td>{dash(row.vendor)}</td>
                            <td>{dash(row.model)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </section>
);

/** "Assets Requiring Attention" — unresolved hardening findings, worst first. */
const AssetsRequiringAttention = ({ items }) => (
    <section className="ov-card ov-card-medium">
        <h3 className="ov-card-title">Assets Requiring Attention</h3>
        <div className="ov-table-wrapper">
            <table className="ov-table">
                <thead>
                    <tr>
                        <th>Asset</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    {items.length === 0 && (
                        <tr>
                            <td colSpan={2} className="ov-table-empty">
                                No assets with unresolved findings.
                            </td>
                        </tr>
                    )}
                    {items.map((row) => (
                        <tr key={row.asset_id}>
                            <td>{dash(row.asset_name)}</td>
                            <td>{dash(row.active_findings_count)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </section>
);

/** "2026-08-18" -> "8/18", matching the design's compact axis labels. */
const dayLabel = (period) => {
    const parts = String(period).split("-");
    return parts.length === 3 ? `${Number(parts[1])}/${Number(parts[2])}` : period;
};

/**
 * "Security Trend": one bar per day over the last 30 days.
 *
 * Drawn with plain elements rather than a chart library — the design is a flat
 * column per point with its value on top, and recharts would fight the fixed
 * 18px bar width the mock specifies.
 */
const SecurityTrend = ({ points, message }) => (
    <section className="ov-card ov-card-trend">
        <h3 className="ov-card-title">Security Trend</h3>
        {points.length === 0 ? (
            <p className="ov-empty">
                {message || "No audit history in the last 30 days."}
            </p>
        ) : (
            <div className="ov-trend">
                {points.map((p) => {
                    const value = Math.max(0, Math.min(100, p.average_compliance));
                    return (
                        <div className="ov-trend-col" key={p.period}>
                            {/* The value sits above a fixed-height track so a
                                bar's height is a true share of the scale — with
                                the label inside the flex flow, tall bars all
                                clipped to the same height. */}
                            <span className="ov-trend-value">
                                {Math.round(value)}%
                            </span>
                            <span className="ov-trend-track">
                                <span
                                    className="ov-trend-bar"
                                    style={{ height: `${value}%` }}
                                    title={`${p.period}: ${Math.round(value)}% (${
                                        p.session_count
                                    } audits)`}
                                />
                            </span>
                            <span className="ov-trend-label">
                                {dayLabel(p.period)}
                            </span>
                        </div>
                    );
                })}
            </div>
        )}
    </section>
);

/**
 * "Recent Security Events": cross-module activity, newest first.
 *
 * Two columns per row in the design — where it happened, and what happened —
 * so the module label and the action title are shown side by side rather than
 * as a conventional table.
 */
const RecentSecurityEvents = ({ items, message }) => (
    <section className="ov-card ov-card-events">
        <h3 className="ov-card-title">Recent Security Events</h3>
        {items.length === 0 ? (
            <p className="ov-empty">{message || "No activity recorded yet."}</p>
        ) : (
            <ul className="ov-events">
                {items.map((event) => (
                    <li className="ov-event" key={event.id}>
                        <span className="ov-event-module">
                            {event.module_label || event.module || "—"}
                        </span>
                        <span className="ov-event-title">
                            {event.title}
                            {event.result === "failed" && (
                                <span className="ov-event-failed">failed</span>
                            )}
                        </span>
                    </li>
                ))}
            </ul>
        )}
    </section>
);

/**
 * The main dashboard.
 *
 * Assembled from the risk, audit and hardening modules rather than one
 * dashboard endpoint, so a user missing one of those permissions still gets
 * the rest of the page.
 */
export const OverviewDashboard = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const state = useSelector((s) => s.overviewDashboard);
    const { isLoading, error, riskSummary } = state;

    useEffect(() => {
        dispatch(fetchOverviewDashboard());
    }, [dispatch]);

    if (isLoading && !riskSummary) {
        return (
            <div className="ov-page">
                <p className="ov-state">Loading dashboard…</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="ov-page">
                <p className="ov-state ov-state-error">
                    Failed to load dashboard: {error}
                </p>
            </div>
        );
    }

    return (
        <div className="ov-page">
            <div className="ov-metrics">
                {headlineMetrics(state).map((metric) => (
                    <MetricCard key={metric.key} metric={metric} />
                ))}
            </div>

            <div className="ov-modules">
                {moduleCards(state).map((card) => (
                    <ModuleCard key={card.key} card={card} onOpen={navigate} />
                ))}
            </div>

            <TopRiskyAssets items={state.topRisky?.items || []} />

            <SecurityTrend
                points={state.complianceTrend?.points || []}
                message={state.complianceTrend?.message}
            />

            <ComplianceVsHardening
                compliance={complianceScore(state.auditOverview)}
                hardening={hardeningScore(state.hardeningOverview)}
            />

            <AssetsRequiringAttention
                items={state.requiringAttention?.items || []}
            />

            <RecentSecurityEvents
                items={state.recentEvents?.items || []}
                message={state.recentEvents?.message}
            />
        </div>
    );
};

export default OverviewDashboard;
