import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import api from "../../config/api";
import { RISK_LEVEL_LABELS } from "../../store/riskSlice";
import { RISK_LEVEL_BADGES, RISK_LEVEL_COLORS } from "./riskConstants";
import { FACTOR_LABELS } from "../Overview/overviewMetrics";
import { Figure, TopAssets, TrendChart } from "../Overview/DashboardParts";
import { tb, tv } from "../../i18n/backendText";
import { t, n } from "../../i18n";
import "../../assets/OverviewDashboard.css";
import "../../assets/RiskAsset.css";

const LEVELS = ["critical", "high", "medium", "low", "informational"];

/** Where to work on each factor. */
const FACTOR_LINKS = {
    criticality: "/risk/assets",
    asset_risk: "/assets/inventory",
    zone: "/risk/assets",
    open_ports: "/risk/exposure",
    audit: "/audit",
    hardening: "/hardening/overview",
    vulnerability: "/cve",
};
const FACTOR_COLORS = {
    criticality: "#7C3AED", asset_risk: "#0EA5E9", zone: "#F59E0B", open_ports: "#14B8A6",
    audit: "#2563EB", hardening: "#22C55E", vulnerability: "#DC2626",
};

const REASON_LABELS = {
    missing_audit: t("Never audited"),
    missing_port_scan: t("No port scan"),
    missing_zone: t("No zone chosen"),
    missing_criticality: t("No criticality chosen"),
    missing_asset_risk: t("No asset risk level"),
};
const REASON_ACTIONS = {
    missing_audit: t("Audit a group"),
    missing_port_scan: t("Run a discovery"),
    missing_zone: t("Set the zone"),
    missing_criticality: t("Set the criticality"),
    missing_asset_risk: t("Edit the asset"),
};

/** What builds the risk: each factor's average points and share, as one bar and a list. */
const Factors = ({ factors, average }) => {
    const shown = factors.filter((f) => f.average > 0);
    return (
        <section className="ovd-card">
            <h2 className="ovd-title">{t("What builds the risk")}</h2>
            <p className="ovd-sub">
                {t("Average points each factor adds to an asset's score (average score {{avg}}). Fix the biggest first.",
                    { avg: n(average ?? 0) })}
            </p>
            {shown.length === 0 ? <p className="ovd-muted">{t("No assets have a risk score yet.")}</p> : (
                <>
                    <div className="rio-stack" aria-hidden="true">
                        {shown.map((f) => <span key={f.key} style={{ width: `${f.share}%`, background: FACTOR_COLORS[f.key] }}
                                                title={FACTOR_LABELS[f.key]} />)}
                    </div>
                    <ul className="rio-factors">
                        {factors.map((f) => (
                            <li key={f.key}>
                                <Link to={FACTOR_LINKS[f.key]} className="rio-factor">
                                    <i className="rio-dot" style={{ background: FACTOR_COLORS[f.key] }} aria-hidden="true" />
                                    <span className="rio-factor-name">{FACTOR_LABELS[f.key]}</span>
                                    <span className="rio-factor-points">{t("{{points}} points", { points: n(f.average) })}</span>
                                    <span className="rio-factor-share">{n(`${f.share}%`)}</span>
                                </Link>
                            </li>
                        ))}
                    </ul>
                </>
            )}
        </section>
    );
};

/** Assets per zone and level; every number opens the risk list filtered to it. */
const ZoneMatrix = ({ rows }) => {
    if (!rows.length) return null;
    // "Informational" only when some asset is at that level
    const levels = LEVELS.filter((lv) => lv !== "informational" || rows.some((r) => r.counts[lv]));
    const max = Math.max(1, ...rows.flatMap((r) => levels.map((lv) => r.counts[lv])));
    return (
        <section className="ovd-card">
            <h2 className="ovd-title">{t("Zone by risk level")}</h2>
            <p className="ovd-sub">{t("Where the risk sits: assets in each zone at each level.")}</p>
            <div className="ovd-table-wrap">
                <table className="ovd-table rio-matrix">
                    <thead>
                        <tr>
                            <th>{t("Zone")}</th>
                            {levels.map((lv) => <th key={lv}>{RISK_LEVEL_LABELS[lv] || lv}</th>)}
                            <th>{t("Total")}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((r) => {
                            const zoneQuery = r.zone_id ? `zone=${r.zone_id}&` : "";
                            return (
                                <tr key={r.zone_id ?? "none"}>
                                    <td>{r.zone_id ? <Link to={`/risk/assets?zone=${r.zone_id}`} className="ovd-asset"><bdi>{tv(r.zone_name)}</bdi></Link>
                                        : <span className="ovd-muted-inline">{t("No zone")}</span>}</td>
                                    {levels.map((lv) => {
                                        const c = r.counts[lv];
                                        if (!c) return <td key={lv} className="rio-cell is-zero">{n(0)}</td>;
                                        const tint = RISK_LEVEL_BADGES[lv];
                                        const strength = 0.35 + 0.65 * (c / max);
                                        return (
                                            <td key={lv} className="rio-cell">
                                                <Link to={`/risk/assets?${zoneQuery}level=${lv}`} className="rio-cell-link"
                                                      style={{ background: tint.bg, color: tint.fg, opacity: strength }}>
                                                    {n(c)}
                                                </Link>
                                            </td>
                                        );
                                    })}
                                    <td className="rio-total">{n(r.total)}</td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </section>
    );
};

/** Why scores are incomplete, with the page that fixes each reason, and the first such assets. */
const Incomplete = ({ data }) => {
    if (!data || !data.total) return null;
    return (
        <section className="ovd-card">
            <div className="ovd-trend-head">
                <h2 className="ovd-title">{t("Incomplete scores")}</h2>
                <Link to="/risk/assets?incomplete=1" className="ovd-more">{t("All incomplete assets ({{count}})", { count: n(data.total) })}</Link>
            </div>
            <p className="ovd-sub">{t("These scores lean on defaults. Fill the gaps so the score reflects the asset.")}</p>
            <div className="rio-reasons">
                {data.reasons.map((r) => (
                    <Link key={r.key} to={r.link} className="ovd-tile is-missing">
                        <span className="ovd-tile-count">{n(r.count)}</span>
                        <span>{REASON_LABELS[r.key] || r.key}</span>
                        <span className="rio-action">{REASON_ACTIONS[r.key] || t("Open")}</span>
                    </Link>
                ))}
            </div>
            <ul className="rio-incomplete">
                {data.assets.map((a) => (
                    <li key={a.asset_id}>
                        <Link to={`/risk/assets/${a.asset_id}`} className="ovd-asset">{a.asset_name}</Link>
                        <span dir="ltr" className="rio-ip">{a.ip_address}</span>
                        <span className="rio-why">{a.reasons.map((x) => REASON_LABELS[x] || x).join(t(", "))}</span>
                    </li>
                ))}
            </ul>
        </section>
    );
};

/**
 * Risk overview (GET /api/dashboard/risk): how much risk there is, what builds it, where it sits, where
 * it is heading, which scores are incomplete and the riskiest assets. Every figure, factor and cell
 * opens the page or filtered list behind it; the full list is Risk of assets.
 */
export const RiskIntelDashboard = () => {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get("/api/dashboard/risk")
            .then(({ data: d }) => alive && setData(d))
            .catch((e) => alive && setError(e.response?.data?.detail || t("Risk data unavailable")));
        return () => { alive = false; };
    }, []);

    if (error) return <div className="ovd-page"><p className="ovd-state ovd-state-error">{t("Failed to load risk data: {{error}}", { error: tb(error) })}</p></div>;
    if (!data) return <div className="ovd-page"><p className="ovd-state">{t("Loading risk data…")}</p></div>;

    const { totals, trend } = data;
    const back = trend.length > 6 ? trend[trend.length - 7] : null;          // 30 days before the last point
    const last = trend.length ? trend[trend.length - 1] : null;
    const change = back && last ? Math.round((last.value - back.value) * 10) / 10 : null;

    return (
        <div className="ovd-page">
            <div className="ovd-figures-row">
                <Figure label={t("Scored assets")} value={totals.scored} to="/risk/assets" />
                <Figure label={t("Risk Score average")} value={totals.average} to="/risk/assets" />
                {["critical", "high", "medium"].map((lv) => (
                    <Figure key={lv} label={t("{{level}} risk", { level: RISK_LEVEL_LABELS[lv] })} value={totals.by_level[lv]}
                            to={`/risk/assets?level=${lv}`} tone={totals.by_level[lv] ? lv : undefined} />
                ))}
                <Figure label={t("Incomplete data")} value={totals.incomplete} to="/risk/assets?incomplete=1" />
                <Figure label={t("Assets with exploited vulnerabilities (KEV)")} value={totals.kev_assets} to="/cve" />
            </div>

            <div className="rio-row">
                <Factors factors={data.factors} average={totals.average} />
                <ZoneMatrix rows={data.matrix} />
            </div>

            <section className="ovd-section">
                <h2 className="ovd-title">{t("Last 90 days")}</h2>
                <div className="ovd-trends">
                    <TrendChart title={t("Average asset risk")} points={trend} change={change} higherIsBetter={false}
                                empty={t("Not enough risk history yet: it builds up as risk is recalculated.")} />
                    <TrendChart title={t("Critical and high assets")} points={trend} showNow={false} domain={[0, "auto"]}
                                lines={[{ key: "critical", color: RISK_LEVEL_COLORS.critical, name: RISK_LEVEL_LABELS.critical },
                                        { key: "high", color: RISK_LEVEL_COLORS.high, name: RISK_LEVEL_LABELS.high }]}
                                empty={t("Not enough risk history yet: it builds up as risk is recalculated.")} />
                </div>
            </section>

            <Incomplete data={data.incomplete} />
            <TopAssets items={data.top_assets} />
        </div>
    );
};

export default RiskIntelDashboard;
