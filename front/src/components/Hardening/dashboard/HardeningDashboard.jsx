/**
 * Hardening overview (GET /api/dashboard/hardening), in five parts: how hardening is going, what needs a
 * person (failed changes with their error and a way back, changes not verified or not holding, assets
 * hardened since their last audit), controls still missing with the way to fix them, what hardening
 * changed in risk terms, and how far it reaches. Every figure and row opens the page behind it.
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import api from "../../../config/api";
import { Figure } from "../../Overview/DashboardParts";
import { RISK_LEVEL_BADGES } from "../../Risk/riskConstants";
import { formatDateTime } from "../../../utils/dates";
import { tb, tv } from "../../../i18n/backendText";
import { t, n } from "../../../i18n";
import { ReportShortcut } from "../../Reports/ReportShortcut.jsx";
import "../../../assets/OverviewDashboard.css";
import "../../../assets/AssetManagementDashboard.css";
import "../../../assets/HardeningDashboard.css";

const STATUS_LABELS = {
    success: t("Succeeded"), failed: t("Failed"), pending: t("Pending"), executing: t("Running"), blocked: t("Blocked"),
};
const SEVERITY_LABELS = { critical: t("Critical"), high: t("High"), medium: t("Medium"), low: t("Low") };

const Severity = ({ value }) => {
    const key = String(value || "").toLowerCase();
    const tint = RISK_LEVEL_BADGES[key];
    return tint ? <span className="hdo-pill" style={{ background: tint.bg, color: tint.fg }}>{SEVERITY_LABELS[key] || value}</span>
        : <span className="hdo-muted">—</span>;
};

const Control = ({ number, title }) => (
    <span className="hdo-control"><b dir="ltr">{number}</b>{title && <span><bdi>{tb(title)}</bdi></span>}</span>
);

const AssetLink = ({ id, name }) => <Link to={`/assets/inventory/${id}`} className="ovd-asset">{name}</Link>;

/** Part 2: one list of things a person has to look at. */
const AttentionList = ({ title, hint, total, children, action }) => (
    <section className="ovd-card hdo-attention">
        <div className="ovd-trend-head">
            <h3 className="ovd-title">{title}</h3>
            <span className={`hdo-count${total ? " is-on" : ""}`}>{n(total)}</span>
            {action}
        </div>
        <p className="ovd-sub">{hint}</p>
        {total === 0 ? <p className="hdo-clear"><i className="fa-solid fa-circle-check" aria-hidden="true" /> {t("Nothing here.")}</p>
            : <ul className="hdo-list">{children}</ul>}
    </section>
);

export const HardeningDashboard = () => {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get("/api/dashboard/hardening")
            .then(({ data: d }) => alive && setData(d))
            .catch((e) => alive && setError(e.response?.data?.detail || t("Could not load the hardening overview")));
        return () => { alive = false; };
    }, []);

    if (error) return <div className="ovd-page"><p className="ovd-state ovd-state-error">{tb(error)}</p></div>;
    if (!data) return <div className="ovd-page"><p className="ovd-state">{t("Loading hardening data…")}</p></div>;

    const { figures: f, attention: at, missing, impact, coverage } = data;
    const riskDrop = impact.risk.assets ? Math.round((impact.risk.before - impact.risk.now) * 10) / 10 : null;

    return (
        <div className="ovd-page">
            <div className="amo-head">
                <ReportShortcut template="hardening_changes" className="bkm-btn bkm-btn-sm" />
                <Link to="/hardening" className="ovd-more">{t("Run hardening")}</Link>
            </div>

            {/* 1. How hardening is going */}
            <div className="ovd-figures-row">
                <Figure label={t("Success rate")} value={f.success_rate === null ? null : `${f.success_rate}%`}
                        detail={f.actions_done ? t("{{ok}} of {{all}} changes", { ok: n(f.succeeded), all: n(f.actions_done) }) : null} />
                <Figure label={t("Changes made")} value={f.actions_done} />
                <Figure label={t("Changes in the last 30 days")} value={f.last_30d} />
                <Figure label={t("Assets hardened")} value={f.hardened_assets} />
                <Figure label={t("Assets never hardened")} value={f.never_hardened} />
                <Figure label={t("Failed, not fixed since")} value={f.open_failures} tone={f.open_failures ? "critical" : undefined} />
                <Figure label={t("Pending Actions")} value={f.pending} />
            </div>

            {/* 2. What needs a person */}
            <section className="ovd-section">
                <h2 className="ovd-title">{t("Needs attention")}</h2>
                <div className="hdo-attention-grid">
                    <AttentionList title={t("Failed changes")} total={at.failed.total}
                                   hint={t("Changes that failed and were not made good later. Read the error, restore the backup taken before it if the device misbehaves, and try again.")}
                                   action={<Link to="/hardening?mode=fix-unsuccessful" className="ovd-more">{t("Try again")}</Link>}>
                        {at.failed.items.map((x) => (
                            <li key={x.id}>
                                <div className="hdo-row-head">
                                    <AssetLink id={x.asset_id} name={x.asset_name} />
                                    <Control number={x.check_number} title={x.check_title} />
                                    <span className="hdo-when">{formatDateTime(x.at)}</span>
                                </div>
                                {x.error && <pre className="hdo-error" dir="ltr">{x.error}</pre>}
                                <Link to={x.restore_link} className="hdo-action">
                                    <i className="fa-solid fa-clock-rotate-left" aria-hidden="true" />{" "}
                                    {x.has_backup ? t("Restore the backup from before the change") : t("Backups of this device")}
                                </Link>
                            </li>
                        ))}
                    </AttentionList>

                    <AttentionList title={t("Not verified or not holding")} total={at.unverified.total}
                                   hint={t("Changes that ran but were not confirmed by checking the device afterwards, or that the check still fails. Audit the device again.")}
                                   action={<Link to="/audit/sessions" className="ovd-more">{t("Run audits")}</Link>}>
                        {at.unverified.items.map((x) => (
                            <li key={x.id}>
                                <div className="hdo-row-head">
                                    <AssetLink id={x.asset_id} name={x.asset_name} />
                                    <Control number={x.check_number} title={x.check_title} />
                                    <span className={`hdo-pill ${x.state === "not_holding" ? "is-bad" : "is-warn"}`}>
                                        {x.state === "not_holding" ? t("Check still fails") : t("Not verified")}
                                    </span>
                                </div>
                            </li>
                        ))}
                    </AttentionList>

                    <AttentionList title={t("Hardened since the last audit")} total={at.not_reaudited.total}
                                   hint={t("Their compliance and risk still show the findings from before the change until they are audited again.")}
                                   action={<Link to="/audit/sessions" className="ovd-more">{t("Run audits")}</Link>}>
                        {at.not_reaudited.items.map((x) => (
                            <li key={x.asset_id}>
                                <div className="hdo-row-head">
                                    <AssetLink id={x.asset_id} name={x.asset_name} />
                                    <span dir="ltr" className="hdo-when">{x.ip_address}</span>
                                    <span className="hdo-when">
                                        {t("hardened {{when}}", { when: formatDateTime(x.hardened_at) })}
                                        {" · "}
                                        {x.audited_at ? t("audited {{when}}", { when: formatDateTime(x.audited_at) }) : t("never audited")}
                                    </span>
                                </div>
                            </li>
                        ))}
                    </AttentionList>
                </div>
            </section>

            {/* 3. Controls still missing */}
            <section className="ovd-card">
                <div className="ovd-trend-head">
                    <h2 className="ovd-title">{t("Top Missing Hardening Controls")}</h2>
                    <Link to="/hardening?mode=fix-unsuccessful" className="ovd-more">{t("Fix with hardening")}</Link>
                </div>
                <p className="ovd-sub">{t("Controls failing in each asset's latest audit that no change has fixed, by the number of assets.")}</p>
                <div className="ovd-table-wrap">
                    <table className="ovd-table">
                        <thead>
                            <tr><th>{t("Control")}</th><th>{t("Severity")}</th><th>{t("Assets")}</th><th><span className="hdo-sr">{t("Actions")}</span></th></tr>
                        </thead>
                        <tbody>
                            {missing.length === 0 && <tr><td colSpan={4} className="ovd-empty">{t("No outstanding controls.")}</td></tr>}
                            {missing.map((c) => (
                                <tr key={c.check_number}>
                                    <td><Control number={c.check_number} title={c.check_title} /></td>
                                    <td><Severity value={c.severity} /></td>
                                    <td className="hdo-num">{n(c.affected_assets)}</td>
                                    <td><Link to={c.link} className="hdo-action">{t("Affected assets")}</Link></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>

            {/* 4. What hardening changed */}
            <section className="ovd-section">
                <h2 className="ovd-title">{t("Hardening Impact")}</h2>
                <div className="ovd-figures-row">
                    <Figure label={t("Findings fixed by hardening")} value={impact.findings_fixed}
                            detail={impact.findings_targeted ? t("of {{count}} it was tried on", { count: n(impact.findings_targeted) }) : null} />
                    <Figure label={t("Critical findings fixed")} value={impact.critical_fixed} />
                    <Figure label={t("High findings fixed")} value={impact.high_fixed} />
                    <Figure label={t("Risk before hardening")} value={impact.risk.before}
                            detail={impact.risk.assets ? t("average of {{count}} assets hardened in {{days}} days", { count: n(impact.risk.assets), days: n(impact.risk.days) }) : null} />
                    <Figure label={t("Risk now")} value={impact.risk.now}
                            detail={riskDrop !== null ? (riskDrop >= 0 ? t("{{points}} points lower", { points: n(riskDrop) }) : t("{{points}} points higher", { points: n(-riskDrop) })) : null} />
                </div>
            </section>

            {/* 5. How far it reaches */}
            <section className="ovd-section">
                <h2 className="ovd-title">{t("Reach")}</h2>
                <div className="amo-grid">
                    <section className="ovd-card amo-bars">
                        <h3 className="amo-subtitle">{t("Hardening Coverage By Asset Type")}</h3>
                        <ul>
                            {coverage.by_type.map((c) => {
                                const inner = (
                                    <>
                                        <span className="amo-bar-name"><bdi>{tv(c.name)}</bdi></span>
                                        <span className="amo-bar-track" aria-hidden="true"><span style={{ width: `${c.pct ?? 0}%` }} /></span>
                                        <span className="amo-bar-count">{t("{{hardened}}/{{total}}", { hardened: n(c.hardened), total: n(c.total) })}</span>
                                    </>
                                );
                                return <li key={c.type_id ?? "none"}>{c.link ? <Link to={c.link} className="amo-bar">{inner}</Link>
                                    : <div className="amo-bar is-static">{inner}</div>}</li>;
                            })}
                        </ul>
                    </section>
                    <section className="ovd-card amo-bars">
                        <h3 className="amo-subtitle">{t("Success rate by benchmark level")}</h3>
                        {coverage.by_level.length === 0 ? <p className="ovd-muted">{t("No hardening actions linked to audit levels yet.")}</p> : (
                            <ul>
                                {coverage.by_level.map((lv) => (
                                    <li key={lv.level}>
                                        <div className="amo-bar is-static">
                                            <span className="amo-bar-name">{tv(lv.level)}</span>
                                            <span className="amo-bar-track" aria-hidden="true"><span style={{ width: `${lv.pct ?? 0}%` }} /></span>
                                            <span className="amo-bar-count">{lv.pct === null ? "—" : n(`${Math.round(lv.pct)}%`)}</span>
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </section>
                </div>
                <section className="ovd-card">
                    <h3 className="ovd-title">{t("Recent Hardening Activities")}</h3>
                    <div className="ovd-table-wrap">
                        <table className="ovd-table">
                            <thead><tr><th>{t("Time")}</th><th>{t("Asset")}</th><th>{t("Control")}</th><th>{t("Status")}</th></tr></thead>
                            <tbody>
                                {coverage.recent.length === 0 && <tr><td colSpan={4} className="ovd-empty">{t("No hardening activity yet.")}</td></tr>}
                                {coverage.recent.map((a) => (
                                    <tr key={a.id}>
                                        <td className="hdo-when">{formatDateTime(a.at)}</td>
                                        <td>{a.asset_id ? <AssetLink id={a.asset_id} name={a.asset_name} /> : "—"}</td>
                                        <td><Control number={a.check_number} title={a.check_title} /></td>
                                        <td><span className={`hdo-pill hdo-status-${a.status}`}>{STATUS_LABELS[a.status] || a.status}</span></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>
            </section>
        </div>
    );
};

export default HardeningDashboard;
