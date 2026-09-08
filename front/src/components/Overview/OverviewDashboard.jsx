import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";

import { fetchOverviewDashboard } from "../../store/overviewDashboardSlice";
import {
    headlineMetrics,
    moduleCards,
    complianceScore,
    hardeningScore,
    riskFromSecurityScore,
} from "./overviewMetrics";
import { RiskLevelBadge } from "../Risk/RiskLevelBadge";
import { RiskScoreBadge } from "./RiskScoreBadge";
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

/* The gauge reads as RISK, not health: higher is worse.
 *
 * The backend's security_score is a *health* score — every sub-score is
 * inverted (100 - avg_risk) and its bands run 90+ excellent .. <40 critical.
 * Showing that number under a risk-coloured scale would contradict itself, so
 * the page converts it once, here: riskScore = 100 - security_score. The band
 * a score falls into is then derived from that risk number rather than trusting
 * the backend's health-oriented `score_level`, which would disagree.
 *
 * `width` is each band's true share of the 0-100 scale, so the needle (placed
 * at `risk%`) and the colours use the same scale. */
const RISK_BANDS = [
    { key: "minimal", label: "Minimal", range: "0-9", color: "#16A34A", width: 10 },
    { key: "low", label: "Low", range: "10-24", color: "#22C55E", width: 15 },
    { key: "moderate", label: "Moderate", range: "25-39", color: "#F59E0B", width: 15 },
    { key: "high", label: "High", range: "40-59", color: "#F97316", width: 20 },
    { key: "critical", label: "Critical", range: "60-100", color: "#DC2626", width: 40 },
];

/** Which band a risk score sits in — highest band first, inclusive bounds. */
const riskBandFor = (risk) => {
    if (risk === null || risk === undefined) return null;
    if (risk >= 60) return "critical";
    if (risk >= 40) return "high";
    if (risk >= 25) return "moderate";
    if (risk >= 10) return "low";
    return "minimal";
};

/** "Security Risk Gauge": the overall risk score against its level bands.
 *  Higher is worse — see riskFromSecurityScore. */
const SecurityPostureGauge = ({ securityScore }) => {
    const risk = riskFromSecurityScore(securityScore?.security_score);
    const level = riskBandFor(risk);

    return (
        <section className="ov-card ov-card-medium">
            <h3 className="ov-card-title">Security Risk Gauge</h3>
            <div className="ov-gauge">
                <div className="ov-gauge-readout">
                    <span className="ov-gauge-label">Security Risk</span>
                    <span className="ov-gauge-value">
                        {risk === null ? "—" : `${risk}/100`}
                    </span>
                </div>

                <div className="ov-gauge-track">
                    {RISK_BANDS.map((band) => (
                        <span
                            key={band.key}
                            className={`ov-gauge-band${
                                band.key === level ? " is-active" : ""
                            }`}
                            style={{ background: band.color, width: `${band.width}%` }}
                            title={`${band.label}: ${band.range}`}
                        />
                    ))}
                    {risk !== null && (
                        <span
                            className="ov-gauge-needle"
                            style={{ left: `${Math.min(100, Math.max(0, risk))}%` }}
                        />
                    )}
                </div>

                <div className="ov-gauge-legend">
                    {RISK_BANDS.map((band) => (
                        <span key={band.key} className="ov-gauge-legend-item">
                            <i
                                className="ov-dot"
                                style={{ background: band.color }}
                            />
                            {band.label}: {band.range}
                        </span>
                    ))}
                </div>

                {securityScore?.incomplete_data && (
                    <p className="ov-gauge-note">
                        Some inputs are incomplete, so this score is provisional.
                    </p>
                )}
            </div>
        </section>
    );
};

/* "NGCorion Security Score Breakdown", "Security Trend" and "Recent Security
   Events" were removed from this page while those features are still being
   developed. The endpoints they read (/api/dashboard/security-score,
   .../compliance-trend, /api/events/recent) are untouched, so restoring a
   panel means re-adding its component and its entry in the render below. */

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

/** "Top 20 Risky Assets" — the highest-scoring assets, newest calculation.
 *  Score and level are shown so the ordering is legible; the level badge is the
 *  shared one, so the colours match the Risk Asset and Risk Intelligence pages. */
const TopRiskyAssets = ({ items }) => (
    <section className="ov-card ov-card-wide">
        <h3 className="ov-card-title">Top 20 Risky Assets</h3>
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
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {items.length === 0 && (
                        <tr>
                            <td colSpan={9} className="ov-table-empty">
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
                            <td>
                                <RiskScoreBadge
                                    score={row.final_risk_score}
                                    level={row.risk_level}
                                />
                            </td>
                            <td>
                                <RiskLevelBadge level={row.risk_level} />
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </section>
);

/** "Assets Requiring Attention" — the High and Critical assets by risk
 *  score, worst first, with the same level colours as the Risk pages. */
const ATTENTION_LEVELS = ["critical", "high"];

const AssetsRequiringAttention = ({ items }) => {
    const rows = (items || [])
        .filter((row) => ATTENTION_LEVELS.includes(row.risk_level))
        .slice(0, 10);

    return (
        <section className="ov-card ov-card-medium">
            <h3 className="ov-card-title">Assets Requiring Attention</h3>
            <div className="ov-table-wrapper">
                <table className="ov-table">
                    <thead>
                        <tr>
                            <th>Asset</th>
                            <th>Risk Score</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.length === 0 && (
                            <tr>
                                <td colSpan={3} className="ov-table-empty">
                                    No High or Critical risk assets.
                                </td>
                            </tr>
                        )}
                        {rows.map((row) => (
                            <tr key={row.asset_id}>
                                <td>{dash(row.asset_name)}</td>
                                <td>
                                <RiskScoreBadge
                                    score={row.final_risk_score}
                                    level={row.risk_level}
                                />
                            </td>
                                <td>
                                    <RiskLevelBadge level={row.risk_level} />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </section>
    );
};

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

            <SecurityPostureGauge securityScore={state.securityScore} />

            <div className="ov-modules">
                {moduleCards(state).map((card) => (
                    <ModuleCard key={card.key} card={card} onOpen={navigate} />
                ))}
            </div>

            <TopRiskyAssets items={state.topRisky?.items || []} />

            <ComplianceVsHardening
                compliance={complianceScore(state.auditOverview)}
                hardening={hardeningScore(state.hardeningOverview)}
            />

            <AssetsRequiringAttention
                items={state.requiringAttention?.items || []}
            />
        </div>
    );
};

export default OverviewDashboard;
