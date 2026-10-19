import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { fetchOverviewDashboard } from "../../store/overviewDashboardSlice";
import { tb } from "../../i18n/backendText";
import {
    attentionItems,
    breakdownRows,
    changeTone,
    coverageRows,
    criticalRisks,
    exposedAssets,
    FACTOR_LABELS,
    riskFromSecurityScore,
} from "./overviewMetrics";
import { RiskLevelBadge } from "../Risk/RiskLevelBadge";
import { RiskScoreBadge } from "./RiskScoreBadge";
import { parseUtc } from "../../utils/dates";
import "../../assets/OverviewDashboard.css";
import { t, n, uiLocale } from "../../i18n";

const hasValue = (v) => v !== null && v !== undefined;

/* The score reads as RISK, not health: higher is worse (see riskFromSecurityScore).
 * `width` is each band's true share of the 0-100 scale, so the needle (placed at `risk%`) and the
 * colours use the same scale. */
const RISK_BANDS = [
    { key: "minimal", label: t("Minimal"), range: "0-9", color: "#16A34A", width: 10 },
    { key: "low", label: t("Low"), range: "10-24", color: "#22C55E", width: 15 },
    { key: "moderate", label: t("Moderate"), range: "25-39", color: "#F59E0B", width: 15 },
    { key: "high", label: t("High"), range: "40-59", color: "#F97316", width: 20 },
    { key: "critical", label: t("Critical"), range: "60-100", color: "#DC2626", width: 40 },
];

/** Which band a risk score sits in — highest band first, inclusive bounds. */
const riskBandFor = (risk) => {
    if (!hasValue(risk)) return null;
    if (risk >= 60) return "critical";
    if (risk >= 40) return "high";
    if (risk >= 25) return "moderate";
    if (risk >= 10) return "low";
    return "minimal";
};

const BAND_COLOR = Object.fromEntries(RISK_BANDS.map((b) => [b.key, b.color]));

/** A 30-day change with its arrow, green when it is good news and red when it is not. */
const Change = ({ value, higherIsBetter, unit = "" }) => {
    const tone = changeTone(value, higherIsBetter);
    if (!tone) return null;
    const cls = tone.good === null ? "is-flat" : tone.good ? "is-good" : "is-bad";
    const arrow = { up: "fa-arrow-up", down: "fa-arrow-down", flat: "fa-minus" }[tone.dir];
    const amount = n(`${value > 0 ? "+" : ""}${value}${unit}`);
    return (
        <span className={`ovd-change ${cls}`} title={t("Change over the last 30 days")}>
            <i className={`fa-solid ${arrow}`} aria-hidden="true" /> {amount}
            <span className="ovd-change-when">{t("in 30 days")}</span>
        </span>
    );
};

/** A small figure that opens the page behind it. */
const Figure = ({ label, value, to }) => (
    <Link to={to} className="ovd-figure">
        <span className="ovd-figure-value">{hasValue(value) ? n(value) : "—"}</span>
        <span className="ovd-figure-label">{label}</span>
    </Link>
);

/** Row 1, start: the overall risk score, its band, and the key counts. */
const ScoreCard = ({ securityScore, riskSummary, overview }) => {
    const risk = riskFromSecurityScore(securityScore?.security_score);
    const band = riskBandFor(risk);
    const riskTrend = overview?.trend?.risk;
    return (
        <section className="ovd-card ovd-score">
            <h2 className="ovd-title">{t("Security Risk Score")}</h2>
            {securityScore ? (
                <>
                    <div className="ovd-score-head">
                        <span className="ovd-score-value" style={{ color: band ? BAND_COLOR[band] : undefined }}>
                            {hasValue(risk) ? n(risk) : "—"}
                            <small>{n("/100")}</small>
                        </span>
                        {band && <span className="ovd-band" style={{ background: BAND_COLOR[band] }}>
                            {RISK_BANDS.find((b) => b.key === band).label}</span>}
                    </div>
                    <div className="ovd-gauge" aria-hidden="true">
                        {RISK_BANDS.map((b) => (
                            <span key={b.key} className={`ovd-gauge-band${b.key === band ? " is-active" : ""}`}
                                  style={{ background: b.color, width: `${b.width}%` }} title={`${b.label}: ${n(b.range)}`} />
                        ))}
                        {hasValue(risk) && <span className="ovd-gauge-needle" style={{ insetInlineStart: `${Math.min(100, Math.max(0, risk))}%` }} />}
                    </div>
                    {hasValue(riskTrend?.change) && (
                        <p className="ovd-score-trend">
                            {t("Average asset risk")} <Change value={riskTrend.change} higherIsBetter={false} />
                        </p>
                    )}
                    {securityScore.incomplete_data && (
                        <p className="ovd-note">{t("Some inputs are incomplete, so this score is provisional.")}</p>
                    )}
                </>
            ) : (
                <p className="ovd-muted">{t("The score needs access to risk intelligence.")}</p>
            )}
            <div className="ovd-figures">
                {overview?.assets && <Figure label={t("Assets in the inventory")} value={overview.assets.total} to="/assets/inventory" />}
                {riskSummary && <Figure label={t("Critical Risk Assets")} value={criticalRisks(riskSummary)} to="/risk/assets" />}
                {riskSummary && <Figure label={t("Internet Exposed Assets")} value={exposedAssets(riskSummary)} to="/risk/exposure" />}
            </div>
        </section>
    );
};

/** Row 1, end: the six parts of the score, each opening its module. */
const Breakdown = ({ securityScore }) => {
    const rows = breakdownRows(securityScore);
    if (!rows.length) return null;
    return (
        <section className="ovd-card ovd-breakdown">
            <h2 className="ovd-title">{t("What makes up the score")}</h2>
            <p className="ovd-sub">{t("Risk of each part (higher is worse) and its weight in the score.")}</p>
            <ul className="ovd-parts">
                {rows.map((r) => {
                    const band = riskBandFor(r.risk);
                    return (
                        <li key={r.key}>
                            <Link to={r.to} className="ovd-part">
                                <span className="ovd-part-label">
                                    {r.label}
                                    {r.incomplete && <i className="fa-solid fa-circle-exclamation ovd-part-warn"
                                                        title={t("No data yet: counted as 50 until there is")} />}
                                </span>
                                <span className="ovd-part-bar" aria-hidden="true">
                                    <span style={{ width: `${Math.min(100, r.risk ?? 0)}%`, background: band ? BAND_COLOR[band] : undefined }} />
                                </span>
                                <span className="ovd-part-value">{hasValue(r.risk) ? n(r.risk) : "—"}</span>
                                <span className="ovd-part-weight">{t("weight {{w}}", { w: n(`${r.weight}%`) })}</span>
                            </Link>
                        </li>
                    );
                })}
            </ul>
        </section>
    );
};

const SEVERITY_ICON = { critical: "fa-circle-exclamation", high: "fa-triangle-exclamation", medium: "fa-circle-info", info: "fa-user-check" };

/** Row 2: what someone has to act on now. */
const NeedsAction = ({ overview }) => {
    const items = attentionItems(overview);
    return (
        <section className="ovd-section">
            <h2 className="ovd-title">{t("Needs action")}</h2>
            {items.length === 0 ? (
                <div className="ovd-allclear">
                    <i className="fa-solid fa-circle-check" aria-hidden="true" />
                    {t("Nothing needs action right now in the modules you can see.")}
                </div>
            ) : (
                <div className="ovd-actions">
                    {items.map((i) => (
                        <Link key={i.key} to={i.link} className={`ovd-action sev-${i.severity}`}>
                            <i className={`fa-solid ${SEVERITY_ICON[i.severity] || "fa-circle-info"} ovd-action-icon`} aria-hidden="true" />
                            <span className="ovd-action-count">{n(i.count)}</span>
                            <span className="ovd-action-label">{i.label}</span>
                            <i className="fa-solid fa-chevron-right ovd-action-go" aria-hidden="true" />
                        </Link>
                    ))}
                </div>
            )}
        </section>
    );
};

/** Row 3: how much of the estate each module covers. */
const Coverage = ({ overview }) => {
    const rows = coverageRows(overview);
    if (!rows.length) return null;
    return (
        <section className="ovd-section">
            <h2 className="ovd-title">{t("Coverage")}</h2>
            <div className="ovd-coverage">
                {rows.map((c) => (
                    <Link key={c.key} to={c.link} className="ovd-card ovd-cover">
                        <span className="ovd-cover-label">{c.label}</span>
                        <span className="ovd-cover-value">{hasValue(c.pct) ? n(`${c.pct}%`) : "—"}</span>
                        <span className="ovd-cover-bar" aria-hidden="true">
                            <span style={{ width: `${c.pct ?? 0}%` }} className={c.pct >= 80 ? "is-good" : c.pct >= 50 ? "is-mid" : "is-low"} />
                        </span>
                        <span className="ovd-cover-detail">
                            {t("{{covered}} of {{total}}", { covered: n(c.covered), total: n(c.total) })} {c.unit}
                        </span>
                    </Link>
                ))}
            </div>
        </section>
    );
};

const dayLabel = (iso) => {
    const d = parseUtc(iso);
    return d ? new Intl.DateTimeFormat(uiLocale(), { day: "numeric", month: "short" }).format(d) : "";
};

/** One 90-day line: the latest value of every asset at each point. */
const TrendChart = ({ title, series, higherIsBetter, color, unit, to, empty }) => {
    const data = (series?.points || []).map((p) => ({ label: dayLabel(p.at), value: p.value, assets: p.assets }));
    const last = data.length ? data[data.length - 1].value : null;
    return (
        <section className="ovd-card ovd-trend">
            <div className="ovd-trend-head">
                <Link to={to} className="ovd-title ovd-title-link">{title}</Link>
                {hasValue(last) && <span className="ovd-trend-now">{n(`${last}${unit}`)}</span>}
                <Change value={series?.change} higherIsBetter={higherIsBetter} unit={unit} />
            </div>
            {data.length < 2 ? (
                <p className="ovd-muted">{empty}</p>
            ) : (
                <div className="ovd-chart" dir="ltr">
                    <ResponsiveContainer width="100%" height={200}>
                        <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
                            <CartesianGrid stroke="#EEF0F4" vertical={false} />
                            <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#6C7A93" }} axisLine={false} tickLine={false}
                                   interval="preserveStartEnd" minTickGap={24} />
                            <YAxis domain={[0, 100]} tickFormatter={(v) => n(v)} tick={{ fontSize: 11, fill: "#6C7A93" }}
                                   axisLine={false} tickLine={false} width={32} />
                            <Tooltip formatter={(value, _name, entry) => [
                                t("{{value}} · {{count}} assets", { value: n(`${value}${unit}`), count: n(entry.payload.assets) }), title]} />
                            <Line type="monotone" dataKey="value" stroke={color} strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            )}
        </section>
    );
};

/** Row 4: where risk and compliance have been heading. */
const Trends = ({ overview }) => {
    const trend = overview?.trend || {};
    if (!trend.risk && !trend.compliance) return null;
    return (
        <section className="ovd-section">
            <h2 className="ovd-title">{t("Last 90 days")}</h2>
            <div className="ovd-trends">
                {trend.risk && <TrendChart title={t("Average asset risk")} series={trend.risk} higherIsBetter={false}
                                           color="#DC2626" unit="" to="/risk/overview"
                                           empty={t("Not enough risk history yet: it builds up as risk is recalculated.")} />}
                {trend.compliance && <TrendChart title={t("Average compliance")} series={trend.compliance} higherIsBetter
                                                 color="#2563EB" unit="%" to="/audit"
                                                 empty={t("Not enough audits yet: the line appears after audits on two different days.")} />}
            </div>
        </section>
    );
};

/** Row 5: the riskiest assets and what drives each one. */
const TopAssets = ({ items }) => {
    if (!items) return null;
    return (
        <section className="ovd-card">
            <div className="ovd-trend-head">
                <h2 className="ovd-title">{t("Top 10 risky assets")}</h2>
                <Link to="/risk/assets" className="ovd-more">{t("All assets by risk")}</Link>
            </div>
            <div className="ovd-table-wrap">
                <table className="ovd-table">
                    <thead>
                        <tr>
                            <th>{t("Asset")}</th>
                            <th>{t("IP address")}</th>
                            <th>{t("Risk Score")}</th>
                            <th>{t("Risk Level")}</th>
                            <th>{t("Main factor")}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.length === 0 && (
                            <tr><td colSpan={5} className="ovd-empty">{t("No assets have a risk score yet.")}</td></tr>
                        )}
                        {items.map((row) => (
                            <tr key={row.asset_id}>
                                <td>
                                    <Link to={`/risk/assets/${row.asset_id}`} className="ovd-asset">{row.asset_name}</Link>
                                    {row.kev > 0 && <span className="ovd-kev" title={t("Has vulnerabilities exploited in the wild (KEV)")}>KEV</span>}
                                    {row.incomplete && <i className="fa-solid fa-circle-exclamation ovd-part-warn" title={t("Some data is missing for this asset")} />}
                                </td>
                                <td><span dir="ltr">{row.ip_address || "—"}</span></td>
                                <td><RiskScoreBadge score={row.score} level={row.level} /></td>
                                <td><RiskLevelBadge level={row.level} /></td>
                                <td>
                                    {row.main_factor ? (
                                        <>
                                            {FACTOR_LABELS[row.main_factor] || row.main_factor}
                                            <span className="ovd-share">{t("{{pct}} of the score", { pct: n(`${row.main_factor_share}%`) })}</span>
                                        </>
                                    ) : "—"}
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
 * The main dashboard: the risk score and its parts, what needs action, coverage, the 90-day trends
 * and the riskiest assets. Every section comes from the modules the user may read and is left out
 * otherwise, so a user with only some modules still gets a dashboard of those.
 */
export const OverviewDashboard = () => {
    const dispatch = useDispatch();
    const { isLoading, error, overview, securityScore, riskSummary } = useSelector((s) => s.overviewDashboard);

    useEffect(() => {
        dispatch(fetchOverviewDashboard());
    }, [dispatch]);

    if (isLoading && !overview) {
        return <div className="ovd-page"><p className="ovd-state">{t("Loading dashboard…")}</p></div>;
    }
    if (error) {
        return (
            <div className="ovd-page">
                <p className="ovd-state ovd-state-error">{t("Failed to load dashboard: {{error}}", { error: tb(error) })}</p>
            </div>
        );
    }

    return (
        <div className="ovd-page">
            <div className="ovd-row ovd-row-top">
                <ScoreCard securityScore={securityScore} riskSummary={riskSummary} overview={overview} />
                <Breakdown securityScore={securityScore} />
            </div>
            <NeedsAction overview={overview} />
            <Coverage overview={overview} />
            <Trends overview={overview} />
            <TopAssets items={overview?.top_assets} />
        </div>
    );
};

export default OverviewDashboard;
