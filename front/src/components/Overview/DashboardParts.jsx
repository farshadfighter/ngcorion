/**
 * Pieces the overview pages share (the dashboard, assets, risk and hardening overviews), so a figure,
 * a coverage tile, a trend or the top-assets table looks and reads the same on each.
 * Styles: assets/OverviewDashboard.css (.ovd-*).
 */
import React from "react";
import { Link } from "react-router-dom";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { changeTone, FACTOR_LABELS, hasValue } from "./overviewMetrics";
import { RiskLevelBadge } from "../Risk/RiskLevelBadge";
import { RiskScoreBadge } from "./RiskScoreBadge";
import { parseUtc } from "../../utils/dates";
import { t, n, uiLocale } from "../../i18n";

/** A 30-day change with its arrow, green when it is good news and red when it is not. */
export const Change = ({ value, higherIsBetter, unit = "" }) => {
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

/** A figure that opens the page behind it; without `to`, a plain box. */
export const Figure = ({ label, value, to, detail, tone }) => {
    const body = (
        <>
            <span className={`ovd-figure-value${tone ? ` is-${tone}` : ""}`}>{hasValue(value) ? n(value) : "—"}</span>
            <span className="ovd-figure-label">{label}</span>
            {detail && <span className="ovd-figure-detail">{detail}</span>}
        </>
    );
    return to ? <Link to={to} className="ovd-figure">{body}</Link> : <div className="ovd-figure is-static">{body}</div>;
};

/** Coverage tiles: rows from overviewMetrics.coverageRows. */
export const CoverageTiles = ({ rows }) => (
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
);

const dayLabel = (iso) => {
    const d = parseUtc(iso);
    return d ? new Intl.DateTimeFormat(uiLocale(), { day: "numeric", month: "short" }).format(d) : "";
};

/**
 * A 90-day line chart. `points` are [{at, value, ...}]; `lines` the series to draw
 * ([{key, color, name}], by default the one "value"); `domain` the y scale (0-100 unless set).
 */
export const TrendChart = ({ title, points, change, higherIsBetter, unit = "", to, empty,
                             lines = [{ key: "value", color: "#DC2626" }], domain = [0, 100], showNow = true }) => {
    const data = (points || []).map((p) => ({ ...p, label: dayLabel(p.at) }));
    const last = data.length ? data[data.length - 1][lines[0].key] : null;
    return (
        <section className="ovd-card ovd-trend">
            <div className="ovd-trend-head">
                {to ? <Link to={to} className="ovd-title ovd-title-link">{title}</Link> : <h3 className="ovd-title">{title}</h3>}
                {showNow && hasValue(last) && <span className="ovd-trend-now">{n(`${last}${unit}`)}</span>}
                <Change value={change} higherIsBetter={higherIsBetter} unit={unit} />
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
                            <YAxis domain={domain} allowDecimals={false} tickFormatter={(v) => n(v)}
                                   tick={{ fontSize: 11, fill: "#6C7A93" }} axisLine={false} tickLine={false} width={32} />
                            <Tooltip formatter={(value, name, entry) => [
                                lines.length > 1 ? n(value)
                                    : t("{{value}} · {{count}} assets", { value: n(`${value}${unit}`), count: n(entry.payload.assets) }),
                                lines.length > 1 ? name : title]} />
                            {lines.length > 1 && <Legend iconType="plainline" wrapperStyle={{ fontSize: 12 }} />}
                            {lines.map((l) => (
                                <Line key={l.key} type="monotone" dataKey={l.key} name={l.name || title} stroke={l.color}
                                      strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
                            ))}
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            )}
        </section>
    );
};

/** The riskiest assets and what drives each one (GET /api/dashboard/overview or /risk, top_assets). */
export const TopAssets = ({ items }) => {
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
