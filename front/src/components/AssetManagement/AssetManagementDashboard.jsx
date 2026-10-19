/**
 * Assets overview (GET /api/dashboard/assets): what the inventory holds, which details are missing,
 * how much of it the other modules cover, breakdowns by type, vendor, operating system, zone and
 * status, and the newest assets. Every figure, row and bar opens the list it counts.
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api";
import { formatDate } from "../../utils/dates";
import { tb, tv } from "../../i18n/backendText";
import { t, n } from "../../i18n";
import { coverageRows } from "../Overview/overviewMetrics";
import { CoverageTiles, Figure } from "../Overview/DashboardParts";
import "../../assets/OverviewDashboard.css";
import "../../assets/AssetManagementDashboard.css";

const QUALITY_LABELS = {
    no_owner: t("No owner"),
    no_ip: t("No IP address"),
    no_os: t("No operating system"),
    no_location: t("No location"),
    no_zone: t("Network zone not chosen (risk uses a default)"),
};

const STATUS_ORDER = ["active", "standby", "inactive", "unknown", "decommissioned"];

/** Values with bars to scale, each a link to the filtered asset list; the rest as "Other". */
const BarList = ({ title, rows, unset, unsetLabel, name = (r) => r.name }) => {
    const max = Math.max(1, ...rows.map((r) => r.count));
    return (
        <section className="ovd-card amo-bars">
            <h3 className="amo-subtitle">{title}</h3>
            {rows.length === 0 ? <p className="ovd-muted">{t("No data")}</p> : (
                <ul>
                    {rows.map((r, i) => {
                        const inner = (
                            <>
                                <span className="amo-bar-name" title={r.other ? undefined : name(r)}><bdi>{r.other ? t("Other") : name(r)}</bdi></span>
                                <span className="amo-bar-track" aria-hidden="true"><span style={{ width: `${(100 * r.count) / max}%` }} /></span>
                                <span className="amo-bar-count">{n(r.count)}</span>
                            </>
                        );
                        return <li key={r.key ?? `other-${i}`}>{r.link ? <Link to={r.link} className="amo-bar">{inner}</Link>
                            : <div className="amo-bar is-static">{inner}</div>}</li>;
                    })}
                </ul>
            )}
            {unset > 0 && <p className="amo-unset">{unsetLabel}: <b>{n(unset)}</b></p>}
        </section>
    );
};

export const AssetManagementDashboard = () => {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get("/api/dashboard/assets")
            .then(({ data: d }) => alive && setData(d))
            .catch((e) => alive && setError(e.response?.data?.detail || t("Could not load the assets overview")));
        return () => { alive = false; };
    }, []);

    if (error) return <div className="ovd-page"><p className="ovd-state ovd-state-error">{tb(error)}</p></div>;
    if (!data) return <div className="ovd-page"><p className="ovd-state">{t("Loading dashboard…")}</p></div>;

    const { totals, license, unknown_devices: unknown } = data;
    const licenseText = license.unlimited ? t("Unlimited")
        : license.max_assets ? t("{{used}} of {{max}}", { used: n(license.used), max: n(license.max_assets) }) : null;
    const coverage = coverageRows({ coverage: data.coverage });
    const statusRows = STATUS_ORDER.filter((s) => totals.by_status[s])
        .map((s) => ({ key: s, name: tv(s), count: totals.by_status[s], link: `/assets/inventory?status=${s}` }));

    return (
        <div className="ovd-page">
            <div className="amo-head">
                <Link to="/assets/inventory" className="ovd-more">{t("Open the asset list")}</Link>
            </div>

            <div className="ovd-figures-row">
                <Figure label={t("Assets in the inventory")} value={totals.total} to="/assets/inventory" />
                <Figure label={t("Added in the last 7 days")} value={totals.new_7d} to="/assets/inventory?added=7" />
                <Figure label={t("Added in the last 30 days")} value={totals.new_30d} to="/assets/inventory?added=30" />
                {licenseText && (
                    <Figure label={t("License use")} value={license.unlimited ? null : license.used}
                            detail={license.over_limit ? t("Over the license: some assets are not covered") : licenseText} />
                )}
                {unknown && (
                    <Figure label={t("Unknown devices on the network")} value={unknown.open} to={unknown.link}
                            detail={unknown.new_7d ? t("{{count}} new this week", { count: n(unknown.new_7d) }) : null} />
                )}
            </div>

            <section className="ovd-section">
                <h2 className="ovd-title">{t("Missing details")}</h2>
                <div className="amo-quality">
                    {data.quality.map((q) => (q.count ? (
                        <Link key={q.key} to={q.link} className="ovd-tile is-missing">
                            <span className="ovd-tile-count">{n(q.count)}</span>
                            <span>{QUALITY_LABELS[q.key] || q.key}</span>
                            <i className="fa-solid fa-chevron-right ovd-action-go" aria-hidden="true" />
                        </Link>
                    ) : (
                        <div key={q.key} className="ovd-tile is-done">
                            <i className="fa-solid fa-circle-check" aria-hidden="true" />
                            <span>{QUALITY_LABELS[q.key] || q.key}: {t("none")}</span>
                        </div>
                    )))}
                </div>
            </section>

            {coverage.length > 0 && (
                <section className="ovd-section">
                    <h2 className="ovd-title">{t("Coverage")}</h2>
                    <CoverageTiles rows={coverage} />
                </section>
            )}

            <section className="ovd-section">
                <h2 className="ovd-title">{t("What the inventory holds")}</h2>
                <div className="amo-grid">
                    <BarList title={t("Asset Type")} rows={data.by_type} name={(r) => tv(r.name)}
                             unset={data.unclassified.type} unsetLabel={t("No type")} />
                    <BarList title={t("Vendor")} rows={data.by_vendor} unset={data.unclassified.vendor} unsetLabel={t("No vendor")} />
                    <BarList title={t("Operating Systems")} rows={data.by_os} unset={data.unclassified.os} unsetLabel={t("No operating system")} />
                    <BarList title={t("Status")} rows={statusRows} />
                    {data.by_zone.length > 0 && <BarList title={t("Zone")} rows={data.by_zone} name={(r) => tv(r.name)} />}
                </div>
            </section>

            <section className="ovd-card">
                <h2 className="ovd-title">{t("Added last")}</h2>
                <div className="ovd-table-wrap">
                    <table className="ovd-table">
                        <thead>
                            <tr><th>{t("Asset")}</th><th>{t("Type")}</th><th>{t("IP address")}</th><th>{t("Added")}</th></tr>
                        </thead>
                        <tbody>
                            {data.newest.length === 0 && <tr><td colSpan={4} className="ovd-empty">{t("No assets yet.")}</td></tr>}
                            {data.newest.map((a) => (
                                <tr key={a.id}>
                                    <td><Link to={`/assets/inventory/${a.id}`} className="ovd-asset">{a.name}</Link></td>
                                    <td>{a.type ? tv(a.type) : "—"}</td>
                                    <td><span dir="ltr">{a.ip_address || "—"}</span></td>
                                    <td>{formatDate(a.created_at)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
};

export default AssetManagementDashboard;
