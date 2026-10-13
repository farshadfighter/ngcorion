/**
 * Syslog (/noc/syslog): the syslog messages the assets send to NGCorion (UDP/TCP port 514).
 *
 * Messages: newest first, filtered by asset, severity, text and period, "live" refresh every 5 s,
 * more on demand (GET /api/syslog/messages, keyset paging), CSV export of the filter.
 * Sources: which assets send and when they last did; addresses outside the inventory, whose
 * messages are dropped (GET /api/syslog/overview).
 * Settings: on/off, UDP/TCP, retention, storage, which levels are kept - system administrators
 * only (PUT /api/syslog/settings) - and how to point a device at NGCorion.
 * Deep links: ?asset=ID&severity=N&tab=sources|settings (the syslog alerts link here).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSelector } from "react-redux";
import { useSearchParams } from "react-router-dom";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { formatDateTime, formatWhen, relativeDays } from "../../utils/dates.js";
import { errorText } from "../AssetGroups/groupFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Syslog.css";

const SEVERITY = [t("Emergency"), t("Alert"), t("Critical"), t("Error"), t("Warning"), t("Notice"),
    t("Informational"), t("Debug")];
const SEVERITY_FILTER = [
    ["", t("All levels")], ["0", t("Emergency only")], ["1", t("Alert or worse")], ["2", t("Critical or worse")],
    ["3", t("Error or worse")], ["4", t("Warning or worse")], ["5", t("Notice or worse")],
    ["6", t("Informational or worse")],
];
const PERIODS = [["1", t("Last hour")], ["24", t("Last 24 hours")], ["168", t("Last 7 days")],
    ["720", t("Last 30 days")], ["", t("Everything kept")]];
const PAGE = 100;
const LIVE_MS = 5000;

const sevClass = (s) => (s <= 2 ? "bkm-pill-bad" : s === 3 ? "bkm-pill-orange" : s === 4 ? "bkm-pill-amber"
    : s <= 6 ? "bkm-pill-muted" : "bkm-pill-muted sl-debug");

function SeverityPill({ value }) {
    return <span className={`bkm-pill ${sevClass(value)}`} title={`${n(value)}`}>{SEVERITY[value] ?? n(value)}</span>;
}

function sinceFor(hours) {
    return hours ? new Date(Date.now() - Number(hours) * 3600000).toISOString() : undefined;
}

function StatusBanner({ status, isAdmin, onSettings }) {
    if (!status) return null;
    if (!status.enabled) {
        return (
            <div className="bkm-note sl-banner">
                <span className="sl-banner-text">{t("Syslog intake is off: NGCorion does not listen for syslog and no message is received.")}</span>
                {isAdmin && <button type="button" className="bkm-btn bkm-btn-sm" onClick={onSettings}>{t("Turn on")}</button>}
            </div>
        );
    }
    if (status.error || !status.listening) {
        return (
            <div className="bkm-note bkm-note-error sl-banner" role="alert">
                <span className="sl-banner-text">{t("Syslog intake is on but not receiving")}{status.error ? `: ${status.error}` : ""}</span>
            </div>
        );
    }
    const protocols = [status.udp && "UDP", status.tcp && "TCP"].filter(Boolean).join("/");
    return (
        <div className="bkm-note bkm-note-ok sl-banner">
            <span className="sl-live-dot" aria-hidden="true" />
            <span className="sl-banner-text">{t("Listening on {{protocols}} port {{port}}. Only assets in the inventory are accepted, by their IP address.",
                { protocols, port: n(status.published_port) })}</span>
        </div>
    );
}

function Messages({ assets, initial }) {
    const [filters, setFilters] = useState(initial);
    const [query, setQuery] = useState(initial.q || "");
    const [items, setItems] = useState(null);
    const [next, setNext] = useState(null);
    const [error, setError] = useState(null);
    const [live, setLive] = useState(false);
    const [busy, setBusy] = useState(false);
    const [exporting, setExporting] = useState(false);

    const params = useCallback((f) => ({
        asset_id: f.asset || undefined, severity: f.severity === "" ? undefined : f.severity,
        q: f.q || undefined, since: sinceFor(f.hours),
    }), []);

    const load = useCallback((f, before) => {
        return api.get("/api/syslog/messages", { params: { ...params(f), before_id: before, limit: PAGE } })
            .then(({ data }) => {
                setItems((cur) => (before ? [...(cur || []), ...data.items] : data.items));
                setNext(data.next_before_id);
                setError(null);
            })
            .catch((e) => setError(errorText(e, t("Could not load the messages"))))
            .finally(() => setBusy(false));
    }, [params]);

    useEffect(() => { load(filters); }, [filters, load]);
    useEffect(() => {
        if (!live) return undefined;
        const id = setInterval(() => load(filters), LIVE_MS);
        return () => clearInterval(id);
    }, [live, filters, load]);

    const set = (k, v) => setFilters((f) => ({ ...f, [k]: v }));
    const exportCsv = () => {
        setExporting(true);
        api.get("/api/syslog/messages/export.csv", { params: params(filters), responseType: "blob" })
            .then((response) => {
                const disposition = response.headers?.["content-disposition"] || "";
                const name = /filename="([^"]+)"/.exec(disposition)?.[1] || "syslog.csv";
                const url = URL.createObjectURL(response.data);
                const link = document.createElement("a");
                link.href = url;
                link.download = name;
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
            })
            .catch(() => setError(t("Could not export the messages")))
            .finally(() => setExporting(false));
    };

    return (
        <section className="bkm-card bkm-flush">
            <div className="sl-filters">
                <select className="bkm-select" value={filters.asset} onChange={(e) => set("asset", e.target.value)}
                        aria-label={t("Asset")}>
                    <option value="">{t("All assets")}</option>
                    {assets.map((a) => <option key={a.asset_id} value={a.asset_id}>{a.asset_name} · {a.source_ip}</option>)}
                </select>
                <select className="bkm-select" value={filters.severity} onChange={(e) => set("severity", e.target.value)}
                        aria-label={t("Severity")}>
                    {SEVERITY_FILTER.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                </select>
                <select className="bkm-select" value={filters.hours} onChange={(e) => set("hours", e.target.value)}
                        aria-label={t("Period")}>
                    {PERIODS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                </select>
                <form className="bkm-search" role="search" onSubmit={(e) => { e.preventDefault(); set("q", query.trim()); }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={query} onChange={(e) => setQuery(e.target.value)} maxLength={200}
                           placeholder={t("Search the text, app or host name…")} aria-label={t("Search")} />
                </form>
                <span className="sl-grow" />
                <label className="sl-live">
                    <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
                    {t("Live")}
                </label>
                <button type="button" className="bkm-btn bkm-btn-sm" onClick={exportCsv} disabled={exporting || !items?.length}>
                    {exporting ? t("Exporting…") : t("Export CSV")}
                </button>
            </div>
            {error && <div className="bkm-note bkm-note-error sl-pad">{error}</div>}
            {items === null && !error && <div className="bkm-empty">{t("Loading…")}</div>}
            {items?.length === 0 && (
                <div className="bkm-empty">
                    <b>{t("No message matches")}</b>
                    <span>{t("Messages appear here as soon as an asset sends them.")}</span>
                </div>
            )}
            {items?.length > 0 && (
                <div className="bkm-table-wrap">
                    <table className="bkm-table sl-table">
                        <thead>
                            <tr><th>{t("Received")}</th><th>{t("Asset")}</th><th>{t("Severity")}</th><th>{t("Source")}</th><th>{t("Message")}</th></tr>
                        </thead>
                        <tbody>
                            {items.map((m) => (
                                <tr key={m.id}>
                                    <td className="bkm-nowrap" title={m.device_time ? t("Device time: {{time}}", { time: formatDateTime(m.device_time) }) : undefined}>
                                        {formatWhen(m.received_at)}
                                    </td>
                                    <td>
                                        <button type="button" className="sl-asset" onClick={() => set("asset", String(m.asset_id))}>
                                            <b>{m.asset_name}</b>
                                            <span className="bkm-sub bkm-mono">{m.source_ip} · {m.protocol.toUpperCase()}</span>
                                        </button>
                                    </td>
                                    <td><SeverityPill value={m.severity} /></td>
                                    <td dir="ltr" className="sl-app">{m.app_name || m.hostname || "—"}</td>
                                    <td><div className="sl-msg" dir="auto">{m.message}</div></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
            {next && (
                <div className="bkm-card-foot">
                    <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy}
                            onClick={() => { setBusy(true); load(filters, next); }}>
                        {t("Show older messages")}
                    </button>
                </div>
            )}
        </section>
    );
}

function Sources({ data }) {
    return (
        <>
            <section className="bkm-card bkm-flush">
                <div className="bkm-card-head">
                    <div>
                        <h2>{t("Assets sending syslog")}</h2>
                        <p>{t("An asset is recognised by its IP address in the inventory.")}</p>
                    </div>
                </div>
                {data.assets.length === 0 ? (
                    <div className="bkm-empty"><b>{t("No asset has sent syslog yet")}</b>
                        <span>{t("Point the devices at NGCorion (Settings tab).")}</span></div>
                ) : (
                    <div className="bkm-table-wrap">
                        <table className="bkm-table">
                            <thead><tr><th>{t("Asset")}</th><th>{t("Last message")}</th><th>{t("Last 24 hours")}</th><th>{t("Kept in total")}</th><th>{t("Dropped (over the rate)")}</th></tr></thead>
                            <tbody>
                                {data.assets.map((s) => (
                                    <tr key={s.source_ip}>
                                        <td><b>{s.asset_name}</b><span className="bkm-sub bkm-mono">{s.source_ip}{s.last_hostname ? ` · ${s.last_hostname}` : ""}</span></td>
                                        <td title={formatDateTime(s.last_seen)}>{formatWhen(s.last_seen)}</td>
                                        <td>{n(s.last_24h)}</td>
                                        <td>{n(s.received)}</td>
                                        <td>{s.dropped ? <span className="bkm-amber bkm-strong">{n(s.dropped)}</span> : n(0)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
            <section className="bkm-card bkm-flush">
                <div className="bkm-card-head">
                    <div>
                        <h2>{t("Addresses outside the inventory")}</h2>
                        <p>{t("These addresses sent syslog but are not assets, so their messages were dropped. Add the device to the inventory to keep them.")}</p>
                    </div>
                </div>
                {data.unknown.length === 0 ? (
                    <div className="bkm-empty"><b>{t("None")}</b></div>
                ) : (
                    <div className="bkm-table-wrap">
                        <table className="bkm-table">
                            <thead><tr><th>{t("Address")}</th><th>{t("Host name it reports")}</th><th>{t("First seen")}</th><th>{t("Last seen")}</th><th>{t("Messages dropped")}</th></tr></thead>
                            <tbody>
                                {data.unknown.map((s) => (
                                    <tr key={s.source_ip}>
                                        <td className="bkm-mono">{s.source_ip}</td>
                                        <td dir="ltr" className="sl-app">{s.last_hostname || "—"}</td>
                                        <td>{relativeDays(s.first_seen)}</td>
                                        <td title={formatDateTime(s.last_seen)}>{formatWhen(s.last_seen)}</td>
                                        <td>{n(s.dropped)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
        </>
    );
}

function Settings({ data, isAdmin, onSaved, msg, setMsg }) {
    const [form, setForm] = useState(data.settings);
    const [busy, setBusy] = useState(false);
    const host = window.location.hostname;
    const changed = JSON.stringify(form) !== JSON.stringify(data.settings);
    const save = () => {
        setBusy(true);
        setMsg(null);
        const body = { ...form, retention_days: Number(form.retention_days), storage_budget_gb: Number(form.storage_budget_gb),
            store_max_severity: Number(form.store_max_severity) };
        api.put("/api/syslog/settings", body)
            .then(() => { setMsg({ ok: true, text: t("Saved. The listener follows within 15 seconds.") }); onSaved(); })
            .catch((e) => setMsg({ ok: false, text: errorText(e, t("Could not save")) }))
            .finally(() => setBusy(false));
    };
    const flag = (k, label) => (
        <label className="sl-check">
            <input type="checkbox" checked={!!form[k]} disabled={!isAdmin} onChange={(e) => setForm({ ...form, [k]: e.target.checked })} />
            {label}
        </label>
    );
    return (
        <div className="bkm-two sl-settings">
            <section className="bkm-card">
                <h2 className="bkm-h3">{t("Receiving syslog")}</h2>
                {!isAdmin && <p className="bkm-small bkm-muted">{t("Only a system administrator can change these settings.")}</p>}
                <div className="sl-form">
                    {flag("enabled", t("Receive syslog from the assets"))}
                    <div className="sl-row">{flag("udp", "UDP 514")}{flag("tcp", "TCP 514")}</div>
                    <label className="alr-lbl">{t("Keep messages at")}
                        <select className="bkm-select" value={form.store_max_severity} disabled={!isAdmin}
                                onChange={(e) => setForm({ ...form, store_max_severity: e.target.value })}>
                            {SEVERITY.map((label, i) => (
                                <option key={i} value={i}>{i === 7 ? t("Every level") : t("{{level}} or more severe", { level: label })}</option>
                            ))}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Remove messages older than (days)")}
                        <input className="bkm-select" type="number" min={1} max={365} value={form.retention_days} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, retention_days: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Disk space for messages at most (GB)")}
                        <input className="bkm-select" type="number" min={1} max={500} value={form.storage_budget_gb} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, storage_budget_gb: e.target.value })} />
                    </label>
                    <p className="bkm-small bkm-muted">{t("When the messages take more space than this, the oldest are removed first.")}</p>
                    {msg && <div className={`bkm-note ${msg.ok ? "bkm-note-ok" : "bkm-note-error"}`}>{msg.text}</div>}
                    {isAdmin && (
                        <div><button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !changed} onClick={save}>{t("Save")}</button></div>
                    )}
                </div>
            </section>
            <section className="bkm-card">
                <h2 className="bkm-h3">{t("Pointing a device at NGCorion")}</h2>
                <p className="bkm-small bkm-muted">{t("Send to this server's address, port 514. The device must be in the inventory with the same IP address it sends from.")}</p>
                <div className="sl-howto">
                    <b>Cisco IOS</b>
                    <pre dir="ltr">{`logging host ${host} transport udp port 514\nlogging trap informational\nservice timestamps log datetime msec`}</pre>
                    <b>FortiGate</b>
                    <pre dir="ltr">{`config log syslogd setting\n    set status enable\n    set server "${host}"\n    set port 514\nend`}</pre>
                    <b>Linux (rsyslog)</b>
                    <pre dir="ltr">{`# /etc/rsyslog.d/90-ngcorion.conf   (@@ = TCP, @ = UDP)\n*.* @@${host}:514`}</pre>
                </div>
                <p className="bkm-small bkm-muted">{t("Syslog has no sign-in: anyone on the network can send a message that claims to come from an asset's address. TCP is harder to forge than UDP; allow port 514 only from the device networks.")}</p>
            </section>
        </div>
    );
}

export function SyslogPage() {
    const [search, setSearch] = useSearchParams();
    const role = useSelector((s) => s.auth.role);
    const isAdmin = role === "admin";
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [settingsMsg, setSettingsMsg] = useState(null);
    const tab = ["sources", "settings"].includes(search.get("tab")) ? search.get("tab") : "messages";
    const initial = useMemo(() => ({
        asset: search.get("asset") || "", severity: search.get("severity") ?? "", hours: "24", q: "",
    }), [search]);

    const loadOverview = useCallback(() => {
        api.get("/api/syslog/overview")
            .then(({ data: d }) => { setData(d); setError(null); })
            .catch((e) => setError(errorText(e, t("Could not load the syslog overview"))));
    }, []);
    useEffect(() => {
        loadOverview();
        const id = setInterval(loadOverview, 30000);
        return () => clearInterval(id);
    }, [loadOverview]);

    const go = (name) => {
        const p = new URLSearchParams(search);
        if (name === "messages") p.delete("tab"); else p.set("tab", name);
        setSearch(p, { replace: true });
    };
    const severe = data ? data.by_severity_24h.slice(0, 3).reduce((a, b) => a + b, 0) : 0;

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>{t("Syslog")}</h1>
                    <p>{t("What the assets report about themselves: errors, sign-ins, configuration changes, interfaces going down.")}</p>
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {data && <StatusBanner status={data.status} isAdmin={isAdmin} onSettings={() => go("settings")} />}

            {data && (
                <div className="bkm-stats bkm-stats-4">
                    <div className="bkm-stat">
                        <span>{t("Messages · last 24 hours")}</span>
                        <b>{n(data.last_24h)}</b>
                        <small>{t("About {{value}} kept in total", { value: n(data.stored) })}</small>
                    </div>
                    <div className={`bkm-stat ${severe ? "bkm-stat-warn" : ""}`}>
                        <span>{t("Critical or worse · 24 hours")}</span>
                        <b className={severe ? "bkm-red" : ""}>{n(severe)}</b>
                        <small>{t("{{value}} errors and {{value2}} warnings", { value: n(data.by_severity_24h[3]), value2: n(data.by_severity_24h[4]) })}</small>
                    </div>
                    <div className="bkm-stat">
                        <span>{t("Assets sending")}</span>
                        <b className="bkm-navy">{n(data.assets.length)}</b>
                        <small>{t("{{value}} in the last 24 hours", { value: n(data.assets.filter((a) => a.last_24h > 0).length) })}</small>
                    </div>
                    <div className={`bkm-stat ${data.unknown.length ? "bkm-stat-warn" : ""}`}>
                        <span>{t("Addresses outside the inventory")}</span>
                        <b className={data.unknown.length ? "bkm-orange" : ""}>{n(data.unknown.length)}</b>
                        <small>{t("Their messages are dropped")}</small>
                    </div>
                </div>
            )}

            <div className="bkm-chips" role="tablist" aria-label={t("Syslog")}>
                {[["messages", t("Messages")], ["sources", t("Sources")], ["settings", t("Settings")]].map(([k, label]) => (
                    <button key={k} type="button" role="tab" aria-selected={tab === k}
                            className={`bkm-chip ${tab === k ? "is-on" : ""}`} onClick={() => go(k)}>{label}</button>
                ))}
            </div>

            {tab === "messages" && data && <Messages key={`${initial.asset}-${initial.severity}`} assets={data.assets} initial={initial} />}
            {tab === "sources" && data && <Sources data={data} />}
            {tab === "settings" && data && <Settings key={JSON.stringify(data.settings)} data={data} isAdmin={isAdmin}
                                                    onSaved={loadOverview} msg={settingsMsg} setMsg={setSettingsMsg} />}
        </div>
    );
}

export default SyslogPage;
