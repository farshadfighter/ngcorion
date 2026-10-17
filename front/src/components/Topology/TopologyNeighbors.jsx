/**
 * Topology → Neighbours (LLDP / CDP) (GET /api/topology/discovery/neighbors): what each monitored
 * router and switch reports is cabled to its ports, read over SNMP from its own LLDP and CDP tables.
 *
 * Lists: on the map (the neighbour is an asset and its link is drawn), not on the map (an asset,
 * link not drawn: automatic links off), not in the inventory, removed from the map. Per neighbour:
 * the reporting device and port, what the neighbour is (name, description, capabilities), its port,
 * its address; add its link to the map, add it as an asset (prefilled), or show its link on the map.
 * Devices read: how the last read of each device went. Settings: on/off, how often, automatic links
 * (system administrators).
 */
import { useCallback, useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { Link } from "react-router-dom";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { formatDateTime, formatWhen } from "../../utils/dates.js";
import { usePermission } from "../../hooks/usePermission";
import { errorText } from "../AssetGroups/groupFormat.js";
import { AssetIcon } from "../shared/AssetIcon.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Syslog.css";
import "../../assets/UnknownDevices.css";

const PAGE = 100;
const CAPS = {
    router: t("Router"), bridge: t("Switch"), wlan_ap: t("Wireless access point"), phone: t("IP phone"),
    station: t("End station"), repeater: t("Repeater"), docsis: t("Cable modem"),
};
const capsText = (caps) => caps.map((c) => CAPS[c]).filter(Boolean).join(" / ");

const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;

function defaultName(nb) {
    const name = (nb.remote_name || "").replace(/\(.*\)$/, "").split(".")[0].trim();
    if (name) return name;
    return `${(nb.guess_icon || "device").replace(/_/g, "-")}-${(nb.chassis_id || "").replace(/[^0-9a-f]/gi, "").slice(-4)}`;
}

function Banner({ data, canRead, onRead, reading, isAdmin, onSettings }) {
    if (!data.enabled) {
        return (
            <div className="bkm-note sl-banner">
                <span className="sl-banner-text">{t("LLDP/CDP discovery is off: the devices' neighbour tables are not read.")}</span>
                {isAdmin && <button type="button" className="bkm-btn bkm-btn-sm" onClick={onSettings}>{t("Turn on")}</button>}
            </div>
        );
    }
    if (!data.sources.length) {
        return (
            <div className="bkm-note bkm-note-orange sl-banner">
                <span className="sl-banner-text">{t("No device has been read yet. Give the routers and switches an SNMP credential (NOC → Hosts); their neighbour tables are read every {{minutes}} minutes.",
                    { minutes: n(data.interval_minutes) })}</span>
                {canRead && <button type="button" className="bkm-btn bkm-btn-sm" disabled={reading} onClick={onRead}>{reading ? t("Reading…") : t("Read now")}</button>}
            </div>
        );
    }
    const failed = data.sources.filter((s) => !s.ok).length;
    return (
        <div className={`bkm-note sl-banner ${failed ? "bkm-note-orange" : "bkm-note-ok"}`}>
            <span className="sl-live-dot" aria-hidden="true" />
            <span className="sl-banner-text">
                {t("Reading the LLDP and CDP tables of {{count}} devices every {{minutes}} minutes; last read {{when}}.",
                    { count: n(data.sources.length), minutes: n(data.interval_minutes), when: formatWhen(data.last_read_at) })}
                {failed > 0 && ` ${t("{{value}} could not be read.", { value: n(failed) })}`}
            </span>
            {canRead && <button type="button" className="bkm-btn bkm-btn-sm" disabled={reading} onClick={onRead}>{reading ? t("Reading…") : t("Read now")}</button>}
        </div>
    );
}

function AddAssetDrawer({ neighbor, onClose, onDone }) {
    const [types, setTypes] = useState(null);
    const [form, setForm] = useState({ asset_name: defaultName(neighbor), asset_type_id: "", hostname: "", description: "" });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        api.get("/api/asset-types/").then(({ data }) => {
            const list = Array.isArray(data) ? data : data.items || [];
            setTypes(list);
            const match = list.find((x) => x.effective_icon === neighbor.guess_icon) || list[0];
            if (match) setForm((f) => ({ ...f, asset_type_id: String(match.id) }));
        }).catch(() => setTypes([]));
    }, [neighbor.guess_icon]);

    const save = () => {
        setBusy(true);
        setError(null);
        api.post(`/api/topology/discovery/neighbors/${neighbor.id}/asset`, { ...form, asset_type_id: Number(form.asset_type_id),
            hostname: form.hostname || null, description: form.description || null })
            .then(({ data }) => onDone(data))
            .catch((e) => setError(errorText(e, t("Could not add the asset"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="nb-add-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="nb-add-title">{t("Add to the inventory")}</h2>
                        <span className="bkm-sub" dir="auto">{neighbor.remote_name || t("Neighbour without a name")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <dl className="ud-facts">
                        <dt>{t("Management address")}</dt><dd>{neighbor.remote_mgmt_ip ? <Mono>{neighbor.remote_mgmt_ip}</Mono> : "—"}</dd>
                        <dt>{t("MAC address")}</dt><dd>{neighbor.chassis_kind === "mac" ? <Mono>{neighbor.chassis_id}</Mono> : "—"}</dd>
                        <dt>{t("Maker")}</dt><dd dir="auto">{neighbor.vendor || "—"}</dd>
                        <dt>{t("Connected to")}</dt><dd><span dir="auto">{neighbor.device.name}</span> <Mono>{neighbor.local_port}</Mono></dd>
                    </dl>
                    <label className="alr-lbl">{t("Asset name")}
                        <input className="bkm-select" value={form.asset_name} maxLength={255} dir="auto" autoFocus
                               onChange={(e) => setForm({ ...form, asset_name: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Asset type")}
                        <select className="bkm-select" value={form.asset_type_id} disabled={!types}
                                onChange={(e) => setForm({ ...form, asset_type_id: e.target.value })}>
                            {(types || []).map((x) => <option key={x.id} value={x.id}>{x.type_name}</option>)}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Host name (optional)")}
                        <input className="bkm-select" value={form.hostname} maxLength={255} dir="ltr"
                               onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Description (optional)")}
                        <input className="bkm-select" value={form.description} maxLength={2000} dir="auto"
                               onChange={(e) => setForm({ ...form, description: e.target.value })} />
                    </label>
                    <p className="bkm-small bkm-muted">{t("The management address, MAC address and maker are filled in from what the neighbour reports, and its link goes on the map. The asset counts towards the license like any other.")}</p>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={save}
                            disabled={busy || !form.asset_name.trim() || !form.asset_type_id}>
                        {busy ? t("Adding…") : t("Add asset")}
                    </button>
                </footer>
            </aside>
        </div>
    );
}

function NeighborTable({ items, canWrite, onAdd, onLink, onShow }) {
    return (
        <div className="bkm-table-wrap">
            <table className="bkm-table ud-table">
                <thead>
                    <tr>
                        <th>{t("Device and port")}</th><th>{t("Neighbour")}</th><th>{t("Its port")}</th>
                        <th>{t("Address")}</th><th>{t("Last seen")}</th><th />
                    </tr>
                </thead>
                <tbody>
                    {items.map((nb) => (
                        <tr key={nb.id} className={nb.current ? "" : "nb-old"}>
                            <td>
                                <div className="ud-addr">
                                    <Link to={`/noc/hosts/${nb.device.id}`} dir="auto"><b>{nb.device.name}</b></Link>
                                    <span className="bkm-sub"><Mono>{nb.local_port}</Mono><span className="bkm-pill bkm-pill-muted nb-proto">{nb.protocol.toUpperCase()}</span></span>
                                </div>
                            </td>
                            <td>
                                <div className="ud-device">
                                    <AssetIcon icon={nb.guess_icon} size={34} />
                                    <div>
                                        {nb.asset ? <Link to={`/assets/inventory/${nb.asset.id}`} dir="auto"><b>{nb.asset.name}</b></Link>
                                            : <b dir="auto">{nb.remote_name || t("Neighbour without a name")}</b>}
                                        {nb.asset && nb.remote_name && nb.remote_name !== nb.asset.name && <span className="bkm-sub" dir="auto">{nb.remote_name}</span>}
                                        {nb.capabilities.length > 0 && <span className="bkm-sub">{capsText(nb.capabilities)}</span>}
                                        {nb.remote_description && <span className="bkm-small bkm-muted nb-desc" dir="auto" title={nb.remote_description}>{nb.remote_description}</span>}
                                    </div>
                                </div>
                            </td>
                            <td>
                                <div className="ud-addr">
                                    {nb.remote_port ? <Mono>{nb.remote_port}</Mono> : "—"}
                                    {nb.remote_port_desc && nb.remote_port_desc !== nb.remote_port && <span className="bkm-small bkm-muted" dir="auto">{nb.remote_port_desc}</span>}
                                </div>
                            </td>
                            <td>
                                <div className="ud-addr">
                                    {nb.remote_mgmt_ip ? <Mono>{nb.remote_mgmt_ip}</Mono> : null}
                                    {nb.chassis_kind === "mac" && <Mono>{nb.chassis_id}</Mono>}
                                    {!nb.remote_mgmt_ip && nb.chassis_kind !== "mac" && "—"}
                                    {nb.vendor && <span className="bkm-small bkm-muted" dir="auto">{nb.vendor}</span>}
                                </div>
                            </td>
                            <td title={formatDateTime(nb.last_seen_at)}>
                                <div className="nb-stack">
                                    <span className="bkm-nowrap">{formatWhen(nb.last_seen_at)}</span>
                                    {!nb.current && <span className="bkm-pill bkm-pill-orange">{t("Not in the last read")}</span>}
                                </div>
                            </td>
                            <td className="ud-actions"><div className="nb-stack nb-end">
                                {nb.link_id ? (
                                    <>
                                        {nb.link_missing && <span className="bkm-pill bkm-pill-bad nb-state">{t("No longer reported")}</span>}
                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onShow(nb.link_id)}>{t("Show on map")}</button>
                                    </>
                                ) : nb.asset ? (
                                    <>
                                        {nb.suppressed && <span className="bkm-small bkm-muted nb-state">{t("Removed from the map")}</span>}
                                        {canWrite && <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" onClick={() => onLink(nb)}>{t("Add to map")}</button>}
                                    </>
                                ) : canWrite && (
                                    <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" onClick={() => onAdd(nb)}>{t("Add as asset")}</button>
                                )}
                            </div></td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function Sources({ data }) {
    return (
        <section className="bkm-card bkm-flush">
            <div className="bkm-card-head">
                <div>
                    <h2>{t("Devices whose neighbour tables are read")}</h2>
                    <p>{t("Every reachable device with an SNMP credential. A device that runs neither LLDP nor CDP reports no neighbours; the device at the other end of its cables still does.")}</p>
                </div>
            </div>
            {data.sources.length === 0 ? (
                <div className="bkm-empty"><b>{t("None yet")}</b></div>
            ) : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead><tr><th>{t("Device")}</th><th>{t("Last read")}</th><th>{t("Result")}</th><th>{t("Protocols")}</th><th>{t("Neighbours")}</th></tr></thead>
                        <tbody>
                            {data.sources.map((s) => (
                                <tr key={s.asset_id}>
                                    <td><Link to={`/noc/hosts/${s.asset_id}`} dir="auto"><b>{s.name}</b></Link></td>
                                    <td title={formatDateTime(s.last_read_at)}>{formatWhen(s.last_read_at)}</td>
                                    <td>{s.ok ? <span className="bkm-pill bkm-pill-ok">{t("Read successfully")}</span>
                                        : <span className="bkm-pill bkm-pill-bad" title={s.error || ""}>{t("Could not read")}</span>}
                                        {!s.ok && s.error && <span className="bkm-sub bkm-mono ud-err" dir="ltr">{s.error}</span>}</td>
                                    <td>{[s.lldp && "LLDP", s.cdp && "CDP"].filter(Boolean).join(" + ") || <span className="bkm-muted">{t("Neither")}</span>}</td>
                                    <td>{n(s.neighbors)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

function Settings({ data, isAdmin, onSaved }) {
    const [form, setForm] = useState({ enabled: data.enabled, interval_minutes: data.interval_minutes, auto_links: data.auto_links });
    const [msg, setMsg] = useState(null);
    const [busy, setBusy] = useState(false);
    const changed = form.enabled !== data.enabled || Number(form.interval_minutes) !== data.interval_minutes
        || form.auto_links !== data.auto_links;
    const save = () => {
        setBusy(true);
        setMsg(null);
        api.put("/api/topology/discovery/settings", { ...form, interval_minutes: Number(form.interval_minutes) })
            .then(() => { setMsg({ ok: true, text: t("Saved") }); onSaved(); })
            .catch((e) => setMsg({ ok: false, text: errorText(e, t("Could not save")) }))
            .finally(() => setBusy(false));
    };
    return (
        <div className="bkm-two sl-settings">
            <section className="bkm-card">
                <h2 className="bkm-h3">{t("Drawing the map from LLDP and CDP")}</h2>
                {!isAdmin && <p className="bkm-small bkm-muted">{t("Only a system administrator can change these settings.")}</p>}
                <div className="sl-form">
                    <label className="sl-check">
                        <input type="checkbox" checked={form.enabled} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                        {t("Read the LLDP and CDP tables of the monitored devices")}
                    </label>
                    <label className="alr-lbl">{t("Every (minutes)")}
                        <input className="bkm-select" type="number" min={5} max={1440} value={form.interval_minutes} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, interval_minutes: e.target.value })} />
                    </label>
                    <label className="sl-check">
                        <input type="checkbox" checked={form.auto_links} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, auto_links: e.target.checked })} />
                        {t("Put the links found on the map automatically")}
                    </label>
                    <p className="bkm-small bkm-muted">{t("Otherwise the links are listed under “Not on the map” and drawn one by one with “Add to map”. Links drawn by hand are never changed; when the devices report the same cable, the link is only marked as confirmed.")}</p>
                    {msg && <div className={`bkm-note ${msg.ok ? "bkm-note-ok" : "bkm-note-error"}`}>{msg.text}</div>}
                    {isAdmin && <div><button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !changed} onClick={save}>{t("Save")}</button></div>}
                </div>
            </section>
            <section className="bkm-card">
                <h2 className="bkm-h3">{t("What the devices must allow")}</h2>
                <p className="bkm-small bkm-muted">{t("LLDP (or CDP on Cisco) turned on, and read-only SNMP access to these tables (on net-snmp: the view of the community or user):")}</p>
                <div className="sl-howto">
                    <pre dir="ltr">{"LLDP-MIB                     1.0.8802.1.1.2.1\nCISCO-CDP-MIB cdpCacheTable   1.3.6.1.4.1.9.9.23.1.2.1\n\nCisco IOS:   lldp run   (CDP is on by default)\nFortiGate:   set lldp-transmission enable (per port)\nLinux:       lldpd with its SNMP subagent"}</pre>
                </div>
                <p className="bkm-small bkm-muted">{t("A link the devices stop reporting is marked “No longer reported” and raises the “Network link lost” alert; it is removed after 30 days.")}</p>
            </section>
        </div>
    );
}

export function TopologyNeighbors({ onShowLink }) {
    const role = useSelector((s) => s.auth.role);
    const isAdmin = role === "admin";
    const canWrite = usePermission("topology", "write");
    const [view, setView] = useState("all");
    const [query, setQuery] = useState("");
    const [q, setQ] = useState("");
    const [data, setData] = useState(null);
    const [items, setItems] = useState([]);
    const [page, setPage] = useState(1);
    const [error, setError] = useState(null);
    const [notice, setNotice] = useState(null);
    const [reading, setReading] = useState(false);
    const [adding, setAdding] = useState(null);
    const listStatus = ["sources", "settings"].includes(view) ? "all" : view;

    const load = useCallback((p = 1) => {
        return api.get("/api/topology/discovery/neighbors", { params: { status: listStatus, q: q || undefined, page: p, page_size: PAGE } })
            .then(({ data: d }) => {
                setData(d);
                setItems((cur) => (p === 1 ? d.items : [...cur, ...d.items]));
                setPage(p);
                setError(null);
            })
            .catch((e) => setError(errorText(e, t("Could not load the neighbours"))));
    }, [listStatus, q]);

    useEffect(() => { load(1); }, [load]);

    const readNow = () => {
        setReading(true);
        setNotice(null);
        api.post("/api/topology/discovery/read-now")
            .then(({ data: r }) => {
                setNotice({ ok: true, text: t("Read {{devices}} devices: {{neighbors}} neighbours; {{created}} new links on the map, {{missing}} no longer reported.",
                    { devices: n(r.devices_read), neighbors: n(r.neighbors), created: n(r.links_created), missing: n(r.links_missing) }) });
                load(1);
            })
            .catch((e) => setNotice({ ok: false, text: errorText(e, t("Could not read the devices")) }))
            .finally(() => setReading(false));
    };
    const addLink = (nb) => api.post(`/api/topology/discovery/neighbors/${nb.id}/link`)
        .then(() => { setNotice({ ok: true, text: t("The link is on the map.") }); load(1); })
        .catch((e) => setNotice({ ok: false, text: errorText(e, t("Could not save")) }));
    const c = data?.counts;

    return (
        <div className="bkm-page nb-page">
            <div className="bkm-head">
                <div>
                    <h1>{t("Neighbours (LLDP/CDP)")}</h1>
                    <p>{t("What each monitored router and switch reports is cabled to its ports, from its own LLDP and CDP tables over SNMP. The links between assets are drawn on the map by themselves.")}</p>
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {data && <Banner data={data} canRead={canWrite} onRead={readNow} reading={reading} isAdmin={isAdmin} onSettings={() => setView("settings")} />}
            {notice && (
                <div className={`bkm-note ${notice.ok ? "bkm-note-ok" : "bkm-note-error"}`}>
                    {notice.text}
                    {notice.assetId && <> <Link className="bkm-link" to={`/assets/inventory/${notice.assetId}`}>{t("Open the asset")}</Link></>}
                </div>
            )}

            {c && data && (
                <div className="bkm-stats bkm-stats-4">
                    <div className="bkm-stat">
                        <span>{t("Links found")}</span>
                        <b className="bkm-navy">{n(data.found_links)}</b>
                        <small>{t("Drawn on the map from LLDP/CDP")}</small>
                    </div>
                    <div className={`bkm-stat ${data.missing_links ? "bkm-stat-warn" : ""}`}>
                        <span>{t("No longer reported")}</span>
                        <b className={data.missing_links ? "bkm-red" : ""}>{n(data.missing_links)}</b>
                        <small>{t("Links the devices stopped reporting")}</small>
                    </div>
                    <div className={`bkm-stat ${c.unknown ? "bkm-stat-warn" : ""}`}>
                        <span>{t("Not in the inventory")}</span>
                        <b className={c.unknown ? "bkm-orange" : ""}>{n(c.unknown)}</b>
                        <small>{t("Neighbours that are not assets")}</small>
                    </div>
                    <div className="bkm-stat">
                        <span>{t("Not on the map")}</span>
                        <b>{n(c.unlinked + c.suppressed)}</b>
                        <small>{t("Assets whose link is not drawn")}</small>
                    </div>
                </div>
            )}

            <div className="bkm-chips" role="tablist" aria-label={t("Neighbours (LLDP/CDP)")}>
                {[["all", t("All"), c ? c.linked + c.unlinked + c.unknown + c.suppressed : undefined], ["linked", t("On the map"), c?.linked],
                  ["unlinked", t("Not on the map"), c?.unlinked], ["unknown", t("Not in the inventory"), c?.unknown],
                  ["suppressed", t("Removed from the map"), c?.suppressed], ["sources", t("Devices read")], ["settings", t("Settings")]]
                    .map(([k, label, count]) => (
                        <button key={k} type="button" role="tab" aria-selected={view === k}
                                className={`bkm-chip ${view === k ? "is-on" : ""}`} onClick={() => setView(k)}>
                            {label}{count !== undefined && <span className="ud-count">{n(count)}</span>}
                        </button>
                    ))}
            </div>

            {view === "sources" && data && <Sources data={data} />}
            {view === "settings" && data && <Settings key={`${data.enabled}-${data.interval_minutes}-${data.auto_links}`} data={data} isAdmin={isAdmin} onSaved={() => load(1)} />}
            {!["sources", "settings"].includes(view) && (
                <section className="bkm-card bkm-flush">
                    <div className="sl-filters">
                        <form className="bkm-search" role="search" onSubmit={(e) => { e.preventDefault(); setQ(query.trim()); }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                            <input value={query} onChange={(e) => setQuery(e.target.value)} maxLength={100} dir="auto"
                                   placeholder={t("Search name, port, address or description…")} aria-label={t("Search")} />
                        </form>
                    </div>
                    {data && items.length === 0 && (
                        <div className="bkm-empty">
                            <b>{t("Nothing here")}</b>
                            {view === "all" && <span>{t("No device has reported a neighbour yet.")}</span>}
                        </div>
                    )}
                    {items.length > 0 && <NeighborTable items={items} canWrite={canWrite} onAdd={setAdding} onLink={addLink} onShow={onShowLink} />}
                    {data && items.length < data.total && (
                        <div className="bkm-card-foot">
                            <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => load(page + 1)}>
                                {t("Show more ({{value}} left)", { value: n(data.total - items.length) })}
                            </button>
                        </div>
                    )}
                </section>
            )}

            {adding && (
                <AddAssetDrawer neighbor={adding} onClose={() => setAdding(null)}
                                onDone={(r) => {
                                    setAdding(null);
                                    setNotice({ ok: true, text: r.link_id ? t("Added to the inventory and to the map.") : t("Added to the inventory."), assetId: r.asset_id });
                                    load(1);
                                }} />
            )}
        </div>
    );
}

export default TopologyNeighbors;
