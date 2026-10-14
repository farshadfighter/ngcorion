/**
 * One asset, everything NGCorion knows about it (/assets/inventory/:assetId), from
 * GET /api/assets/{id}/360: identity, tags and groups, risk, audits, vulnerabilities, remediation,
 * configuration backups, monitoring (SNMP and syslog), open alerts, topology neighbours, software,
 * hardening and a timeline across all of them. A section the user's permissions do not cover comes
 * back empty and is not shown; each card links to its module's page for the rest.
 */
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { tb } from "../../i18n/backendText.js";
import { formatDateTime, formatWhen, relativeDays } from "../../utils/dates.js";
import { TECHS, errorText } from "../AssetGroups/groupFormat.js";
import { AssetIcon } from "../shared/AssetIcon.jsx";
import "../../assets/BackupModule.css";
import "../../assets/AssetDetail.css";

const SEVERITY = { critical: t("Critical"), high: t("High"), medium: t("Medium"), low: t("Low"),
    warning: t("Warning"), info: t("Information") };
const SEV_PILL = { critical: "bkm-pill-bad", high: "bkm-pill-orange", medium: "bkm-pill-amber", low: "bkm-pill-muted",
    warning: "bkm-pill-orange", info: "bkm-pill-muted" };
const SYSLOG_SEV = [t("Emergency"), t("Alert"), t("Critical"), t("Error"), t("Warning"), t("Notice"),
    t("Informational"), t("Debug")];
const STATUS = { ACTIVE: t("Active"), STANDBY: t("Standby"), INACTIVE: t("Inactive"), DECOMMISSIONED: t("Decommissioned") };
const ASSET_ACTIONS = { create: t("Asset added"), update: t("Asset details changed"), delete: t("Asset deleted"),
    excel_import: t("Imported from Excel") };
const HARDENING_STATUS = { success: t("Done"), failed: t("Failed"), blocked: t("Blocked"), pending: t("Pending"),
    executing: t("Running") };
const RESTORE_STATUS = { succeeded: t("Succeeded"), reverted: t("Auto-reverted"), failed: t("Failed") };

const pct = (v) => (v == null ? "—" : n(`${Math.round(v)}%`));
const tech = (k) => TECHS[k] || k;

function Sev({ value }) {
    return <span className={`bkm-pill ${SEV_PILL[value] || "bkm-pill-muted"}`}>{SEVERITY[value] || value || "—"}</span>;
}

function Card({ title, link, linkLabel, children, sub }) {
    return (
        <section className="bkm-card bkm-flush a360-card">
            <div className="bkm-card-head">
                <div>
                    <h2>{title}</h2>
                    {sub && <p>{sub}</p>}
                </div>
                {link && <Link className="bkm-link a360-more" to={link}>{linkLabel || t("Open")} ›</Link>}
            </div>
            <div className="a360-body">{children}</div>
        </section>
    );
}

function Kv({ label, children }) {
    if (children == null || children === "" || (Array.isArray(children) && !children.length)) return null;
    return <div className="bkm-kv"><span>{label}</span><b dir="auto">{children}</b></div>;
}

function Stats({ d }) {
    const tiles = [];
    if (d.risk) {
        tiles.push(
            <div key="risk" className={`bkm-stat ${["critical", "high"].includes(d.risk.level) ? "bkm-stat-warn" : ""}`}>
                <span>{t("Risk score")}</span>
                <b className={d.risk.level === "critical" ? "bkm-red" : d.risk.level === "high" ? "bkm-orange" : "bkm-navy"}>
                    {d.risk.score == null ? "—" : n(Math.round(d.risk.score))}
                </b>
                <small>{d.risk.score == null ? t("Not calculated yet") : SEVERITY[d.risk.level] || d.risk.level}</small>
            </div>);
    }
    if (d.audits) {
        const last = d.audits.latest[0];
        tiles.push(
            <div key="audit" className="bkm-stat">
                <span>{t("Compliance")}</span>
                <b className="bkm-navy">{last ? pct(last.compliance) : "—"}</b>
                <small>{last ? t("{{tech}} · {{when}}", { tech: tech(last.technology), when: relativeDays(last.completed_at) })
                    : t("Never audited")}</small>
            </div>);
    }
    if (d.cve) {
        tiles.push(
            <div key="cve" className={`bkm-stat ${d.cve.fix_now ? "bkm-stat-warn" : ""}`}>
                <span>{t("Vulnerabilities")}</span>
                <b className={d.cve.fix_now ? "bkm-red" : ""}>{n(d.cve.total)}</b>
                <small>{t("{{value}} to fix now, {{value2}} exploited", { value: n(d.cve.fix_now), value2: n(d.cve.kev) })}</small>
            </div>);
    }
    if (d.remediation) {
        tiles.push(
            <div key="rem" className={`bkm-stat ${d.remediation.overdue ? "bkm-stat-warn" : ""}`}>
                <span>{t("Open remediation")}</span>
                <b className={d.remediation.overdue ? "bkm-orange" : ""}>{n(d.remediation.open)}</b>
                <small>{t("{{value}} overdue", { value: n(d.remediation.overdue) })}</small>
            </div>);
    }
    if (d.backups) {
        tiles.push(
            <div key="bk" className={`bkm-stat ${d.backups.external_changes_30d ? "bkm-stat-warn" : ""}`}>
                <span>{t("Last configuration backup")}</span>
                <b className="a360-stat-text">{d.backups.last_at ? relativeDays(d.backups.last_at) : t("Never")}</b>
                <small>{t("{{value}} changes outside NGCorion in 30 days", { value: n(d.backups.external_changes_30d) })}</small>
            </div>);
    }
    if (d.monitoring) {
        const s = d.monitoring.snmp;
        tiles.push(
            <div key="mon" className={`bkm-stat ${s.reachable === false || d.monitoring.syslog.severe_24h ? "bkm-stat-warn" : ""}`}>
                <span>{t("Monitoring")}</span>
                <b className={`a360-stat-text ${s.reachable === false ? "bkm-red" : ""}`}>
                    {!s.configured ? t("No SNMP") : s.reachable ? t("Reachable") : t("Unreachable")}
                </b>
                <small>{t("{{value}} serious syslog messages in 24 hours", { value: n(d.monitoring.syslog.severe_24h) })}</small>
            </div>);
    }
    return tiles.length ? <div className={`bkm-stats a360-stats a360-stats-${Math.min(tiles.length, 6)}`}>{tiles}</div> : null;
}

function timelineText(e) {
    switch (e.kind) {
        case "asset": return ASSET_ACTIONS[e.action] || e.action;
        case "audit": return e.status === "completed"
            ? t("Audit {{tech}}: {{value}} compliant", { tech: tech(e.text), value: pct(e.value) })
            : t("Audit {{tech}}: {{status}}", { tech: tech(e.text), status: e.status === "failed" ? t("failed") : t("running") });
        case "hardening": return t("Hardening: {{check}} ({{status}})", { check: e.text, status: HARDENING_STATUS[e.status] || e.status });
        case "backup":
            if (e.action === "external") return t("Configuration changed outside NGCorion (+{{added}} −{{removed}})", { added: n(e.added ?? 0), removed: n(e.removed ?? 0) });
            if (e.action === "ngcorion") return t("Configuration changed by NGCorion (+{{added}} −{{removed}})", { added: n(e.added ?? 0), removed: n(e.removed ?? 0) });
            if (e.action === "first") return t("First configuration backup");
            return t("Configuration backup");
        case "change": return t("Device reported a configuration change by {{user}} from {{address}}", {
            user: e.by || t("unknown user"), address: e.from || t("unknown address") });
        case "restore": return t("Configuration restored: {{status}}", { status: RESTORE_STATUS[e.status] || e.status });
        case "alert": return tb(e.text);
        default: return e.text || e.kind;
    }
}

const KIND_LABEL = { asset: t("Inventory"), audit: t("Audit"), hardening: t("Hardening"), backup: t("Backup"),
    restore: t("Restore"), alert: t("Alert"), change: t("Change") };

export function AssetDetailPage() {
    const { assetId } = useParams();
    const [d, setD] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get(`/api/assets/${assetId}/360`)
            .then(({ data }) => { if (alive) { setD(data); setError(null); } })
            .catch((e) => { if (alive) setError(errorText(e, t("Could not load the asset"))); });
        return () => { alive = false; };
    }, [assetId]);

    if (error) return <div className="bkm-page"><div className="bkm-note bkm-note-error">{error}</div></div>;
    if (!d) return <div className="bkm-page"><div className="bkm-card bkm-empty">{t("Loading…")}</div></div>;
    const a = d.asset;

    return (
        <div className="bkm-page a360">
            <div className="bkm-crumb"><Link to="/assets/inventory">{t("Asset inventory")}</Link> › <span dir="auto">{a.name}</span></div>
            <header className="bkm-card a360-head">
                <AssetIcon icon={a.icon} size={56} />
                <div className="a360-title">
                    <h1 dir="auto">{a.name}</h1>
                    <div className="a360-chips">
                        {a.type && <span className="bkm-pill bkm-pill-muted">{a.type}</span>}
                        {a.status && <span className={`bkm-pill ${a.status.toUpperCase() === "ACTIVE" ? "bkm-pill-ok" : "bkm-pill-muted"}`}>{STATUS[a.status.toUpperCase()] || a.status}</span>}
                        {a.ip_address && <span className="bkm-mono a360-ip">{a.ip_address}</span>}
                        {!a.licensed && <span className="bkm-pill bkm-pill-orange">{t("Outside license")}</span>}
                        {a.tags.map((tag) => <span key={tag} className="a360-tag">#{tag}</span>)}
                    </div>
                    {a.groups.length > 0 && (
                        <div className="a360-groups">
                            <span className="bkm-small bkm-muted">{t("Groups:")}</span>
                            {a.groups.map((g) => <Link key={g.id} className="a360-group" to="/assets/groups">{g.name}</Link>)}
                        </div>
                    )}
                </div>
                <nav className="a360-links" aria-label={t("Related pages")}>
                    {d.risk && <Link className="bkm-btn bkm-btn-sm" to={`/risk/assets/${a.id}`}>{t("Risk")}</Link>}
                    {d.backups && <Link className="bkm-btn bkm-btn-sm" to={`/backup?asset=${a.id}`}>{t("Backups")}</Link>}
                    {d.monitoring && <Link className="bkm-btn bkm-btn-sm" to={`/noc/hosts/${a.id}`}>{t("SNMP")}</Link>}
                    {d.monitoring && <Link className="bkm-btn bkm-btn-sm" to={`/noc/syslog?asset=${a.id}`}>{t("Syslog")}</Link>}
                </nav>
            </header>

            <Stats d={d} />

            {d.alerts?.length > 0 && (
                <section className="bkm-card bkm-flush a360-alerts">
                    <div className="bkm-card-head"><div><h2>{t("Open alerts")}</h2></div>
                        <Link className="bkm-link a360-more" to="/alerts">{t("All alerts")} ›</Link></div>
                    <ul className="a360-list">
                        {d.alerts.map((x) => (
                            <li key={x.id}>
                                <Sev value={x.severity} />
                                <span className="a360-grow">
                                    {x.link ? <Link to={x.link}><b>{tb(x.title)}</b></Link> : <b>{tb(x.title)}</b>}
                                    {x.detail && <span className="bkm-sub" dir="auto">{tb(x.detail)}</span>}
                                </span>
                                <span className="bkm-small bkm-muted bkm-nowrap">{formatWhen(x.since)}</span>
                            </li>
                        ))}
                    </ul>
                </section>
            )}

            <div className="bkm-grid a360-grid">
                <div className="a360-col">
                    {d.audits && (
                        <Card title={t("Security audits")} link="/audit/sessions" linkLabel={t("All audits")}
                              sub={t("The latest completed audit of each technology")}>
                            {d.audits.latest.length === 0 ? <p className="bkm-muted a360-empty">{t("Not audited yet.")}</p> : (
                                <table className="bkm-table">
                                    <thead><tr><th>{t("Technology")}</th><th>{t("Compliance")}</th><th>{t("Failed checks")}</th><th>{t("Date")}</th></tr></thead>
                                    <tbody>
                                        {d.audits.latest.map((s) => (
                                            <tr key={s.id}>
                                                <td><Link to={`/audit/sessions/${s.id}`}>{tech(s.technology)}</Link></td>
                                                <td>
                                                    <span className="a360-meter"><span style={{ width: `${Math.round(s.compliance || 0)}%` }} /></span>
                                                    {pct(s.compliance)}
                                                </td>
                                                <td>{t("{{value}} of {{value2}}", { value: n(s.failed ?? 0), value2: n(s.total ?? 0) })}</td>
                                                <td className="bkm-nowrap">{relativeDays(s.completed_at)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </Card>
                    )}

                    {d.cve && (
                        <Card title={t("Vulnerabilities")} link="/cve" linkLabel={t("CVE findings")}
                              sub={t("{{value}} critical, {{value2}} high", { value: n(d.cve.by_severity.critical), value2: n(d.cve.by_severity.high) })}>
                            {d.cve.top.length === 0 ? <p className="bkm-muted a360-empty">{t("No known vulnerability.")}</p> : (
                                <table className="bkm-table">
                                    <thead><tr><th>CVE</th><th>{t("Severity")}</th><th>{t("Product")}</th><th>{t("Fixed in")}</th></tr></thead>
                                    <tbody>
                                        {d.cve.top.map((c) => (
                                            <tr key={c.cve_id}>
                                                <td className="bkm-mono bkm-nowrap">{c.cve_id}{c.kev && <span className="bkm-pill bkm-pill-bad a360-kev">KEV</span>}</td>
                                                <td><Sev value={c.severity} /> {c.cvss != null && <span className="bkm-small bkm-muted">{n(c.cvss)}</span>}</td>
                                                <td dir="ltr" className="a360-ltr">{c.product} {c.installed}</td>
                                                <td dir="ltr" className="a360-ltr">{c.fixed_in || "—"}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </Card>
                    )}

                    {d.remediation && (
                        <Card title={t("Remediation")} link="/remediation" linkLabel={t("All items")}
                              sub={t("{{value}} open, {{value2}} overdue, {{value3}} risks accepted",
                                  { value: n(d.remediation.open), value2: n(d.remediation.overdue), value3: n(d.remediation.accepted) })}>
                            {d.remediation.top.length === 0 ? <p className="bkm-muted a360-empty">{t("Nothing open.")}</p> : (
                                <ul className="a360-list">
                                    {d.remediation.top.map((i) => (
                                        <li key={i.id}>
                                            <Sev value={i.severity} />
                                            <span className="a360-grow" dir="auto">{i.title}</span>
                                            {i.due_at && (
                                                <span className={`bkm-small bkm-nowrap ${new Date(`${i.due_at}Z`) < new Date() ? "bkm-red bkm-strong" : "bkm-muted"}`}>
                                                    {t("Due {{date}}", { date: formatDateTime(i.due_at) })}
                                                </span>
                                            )}
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </Card>
                    )}

                    {d.backups && (
                        <Card title={t("Configuration backups")} link={`/backup?asset=${a.id}`} linkLabel={t("All backups")}
                              sub={d.backups.last_change_at ? t("Last change {{when}}", { when: formatWhen(d.backups.last_change_at) }) : null}>
                            {d.backups.recent.length === 0 ? <p className="bkm-muted a360-empty">{t("No backup yet.")}</p> : (
                                <ul className="a360-list">
                                    {d.backups.recent.map((b) => (
                                        <li key={b.id}>
                                            <span className="bkm-nowrap">{formatWhen(b.created_at)}</span>
                                            <span className="a360-grow">
                                                {b.change_origin === "external" && <span className="bkm-pill bkm-pill-orange">{t("Changed outside NGCorion")}</span>}
                                                {b.change_origin === "ngcorion" && <span className="bkm-pill bkm-pill-run">{t("Changed by NGCorion")}</span>}
                                                {b.change_origin === "first" && <span className="bkm-pill bkm-pill-muted">{t("First backup")}</span>}
                                                {b.change_origin === "unchanged" && <span className="bkm-pill bkm-pill-ok">{t("Unchanged")}</span>}
                                                {(b.added || b.removed) ? <span className="a360-diff"> <b className="a360-plus">+{n(b.added ?? 0)}</b> <b className="a360-minus">−{n(b.removed ?? 0)}</b></span> : null}
                                            </span>
                                            {["external", "ngcorion"].includes(b.change_origin) &&
                                                <Link className="bkm-link" to={`/backup?asset=${a.id}&compare=${b.id}`}>{t("What changed")}</Link>}
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </Card>
                    )}

                    <Card title={t("Timeline")} sub={t("What happened to this asset, newest first")}>
                        {d.timeline.length === 0 ? <p className="bkm-muted a360-empty">{t("Nothing recorded yet.")}</p> : (
                            <ol className="a360-timeline">
                                {d.timeline.map((e, i) => (
                                    <li key={i} className={`a360-ev a360-ev-${e.kind}`}>
                                        <span className="a360-dot" aria-hidden="true" />
                                        <span className="a360-ev-kind">{KIND_LABEL[e.kind] || e.kind}</span>
                                        <span className="a360-grow" dir="auto">
                                            {e.link ? <Link to={e.link}>{timelineText(e)}</Link> : timelineText(e)}
                                        </span>
                                        <span className="bkm-small bkm-muted bkm-nowrap" title={formatDateTime(e.at)}>{formatWhen(e.at)}</span>
                                    </li>
                                ))}
                            </ol>
                        )}
                    </Card>
                </div>

                <div className="a360-col">
                    <Card title={t("Details")}>
                        <Kv label={t("Host name")}>{a.hostname}</Kv>
                        <Kv label={t("Operating system")}>{[a.os_name, a.os_version].filter(Boolean).join(" ")}</Kv>
                        <Kv label={t("Manufacturer / model")}>{[a.manufacturer, a.model].filter(Boolean).join(" ")}</Kv>
                        <Kv label={t("Serial number")}>{a.serial_number}</Kv>
                        <Kv label={t("MAC address")}>{a.mac_address}</Kv>
                        <Kv label={t("Owner")}>{a.owner}</Kv>
                        <Kv label={t("Location")}>{a.location}</Kv>
                        <Kv label={t("Confidentiality")}>{a.confidentiality}</Kv>
                        {d.risk && <Kv label={t("Zone")}>{d.risk.zone}</Kv>}
                        {a.hosted_on && <Kv label={t("Runs on")}><Link to={`/assets/inventory/${a.hosted_on.id}`}>{a.hosted_on.name}</Link></Kv>}
                        {a.hosts.length > 0 && (
                            <Kv label={t("Hosts")}>
                                {a.hosts.map((h, i) => <span key={h.id}>{i > 0 && "، "}<Link to={`/assets/inventory/${h.id}`}>{h.name}</Link></span>)}
                            </Kv>
                        )}
                        <Kv label={t("Added")}>{formatDateTime(a.created_at)}</Kv>
                        {a.description && <p className="bkm-small a360-desc" dir="auto">{a.description}</p>}
                    </Card>

                    {d.monitoring && (
                        <Card title={t("Monitoring")} link={`/noc/syslog?asset=${a.id}`} linkLabel={t("Syslog")}>
                            <Kv label={t("SNMP")}>
                                {!d.monitoring.snmp.configured ? t("Not set up")
                                    : d.monitoring.snmp.reachable ? t("Reachable") : t("Unreachable")}
                            </Kv>
                            {d.monitoring.snmp.uptime_seconds != null && (
                                <Kv label={t("Up for")}>{t("{{value}} days", { value: n(Math.floor(d.monitoring.snmp.uptime_seconds / 86400)) })}</Kv>
                            )}
                            {d.monitoring.snmp.interfaces > 0 && (
                                <Kv label={t("Interfaces")}>
                                    {t("{{value}} in total, {{value2}} down", { value: n(d.monitoring.snmp.interfaces), value2: n(d.monitoring.snmp.interfaces_down) })}
                                </Kv>
                            )}
                            <Kv label={t("Last syslog message")}>{d.monitoring.syslog.last_at ? formatWhen(d.monitoring.syslog.last_at) : t("None")}</Kv>
                            {d.monitoring.syslog.recent.length > 0 && (
                                <ul className="a360-syslog">
                                    {d.monitoring.syslog.recent.map((m) => (
                                        <li key={m.id}>
                                            <span className={`a360-sev a360-sev-${m.severity <= 2 ? "bad" : m.severity <= 4 ? "warn" : "ok"}`}
                                                  title={SYSLOG_SEV[m.severity]} />
                                            <span className="a360-msg" dir="auto">{m.app ? `${m.app}: ` : ""}{m.message}</span>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </Card>
                    )}

                    {d.topology && d.topology.length > 0 && (
                        <Card title={t("Connected to")} link="/topology" linkLabel={t("Topology")}>
                            <ul className="a360-list">
                                {d.topology.map((x, i) => (
                                    <li key={i}>
                                        <AssetIcon icon={x.icon} size={24} />
                                        <span className="a360-grow">
                                            <Link to={`/assets/inventory/${x.asset_id}`}><b dir="auto">{x.name}</b></Link>
                                            {(x.local_interface || x.remote_interface) && (
                                                <span className="bkm-sub bkm-mono" dir="ltr">{x.local_interface || "?"} ↔ {x.remote_interface || "?"}</span>
                                            )}
                                        </span>
                                    </li>
                                ))}
                            </ul>
                        </Card>
                    )}

                    <Card title={t("Software")} link="/assets/software" linkLabel={t("Software inventory")}>
                        {d.software.last_collected_at ? (
                            <>
                                <Kv label={t("Packages and programs")}>{n(d.software.packages)}</Kv>
                                {d.software.services > 0 && <Kv label={t("Services")}>{n(d.software.services)}</Kv>}
                                {d.software.hotfixes > 0 && <Kv label={t("Hotfixes")}>{n(d.software.hotfixes)}</Kv>}
                                <Kv label={t("Collected")}>{formatWhen(d.software.last_collected_at)}</Kv>
                            </>
                        ) : <p className="bkm-muted a360-empty">{t("Not collected yet.")}</p>}
                    </Card>

                    {d.hardening && d.hardening.recent.length > 0 && (
                        <Card title={t("Hardening")} sub={t("{{value}} changes applied", { value: n(d.hardening.succeeded) })}>
                            <ul className="a360-list">
                                {d.hardening.recent.map((h) => (
                                    <li key={h.id}>
                                        <span className={`bkm-pill ${h.status === "success" ? "bkm-pill-ok" : h.status === "failed" ? "bkm-pill-bad" : "bkm-pill-muted"}`}>
                                            {HARDENING_STATUS[h.status] || h.status}
                                        </span>
                                        <span className="a360-grow" dir="auto">{h.title}</span>
                                        <span className="bkm-small bkm-muted bkm-nowrap">{relativeDays(h.at)}</span>
                                    </li>
                                ))}
                            </ul>
                        </Card>
                    )}
                </div>
            </div>
        </div>
    );
}

export default AssetDetailPage;
