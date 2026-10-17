/**
 * Unknown devices (/noc/unknown-devices): addresses the monitored routers and switches see on the
 * network that are not in the inventory (GET /api/noc/endpoints). NGCorion reads their ARP and MAC
 * tables over SNMP; nothing is scanned.
 *
 * Lists: unknown (default), new in the last 24 hours, ignored, in the inventory. Per device: what
 * it probably is (from the maker of its MAC address), its MAC and IP, the switch port it is on,
 * when it was first and last seen; add it as an asset (prefilled) or ignore it, one or several.
 * Devices read: whose tables are read and how the last read went. Settings: on/off and how often
 * (system administrators). Deep link: ?focus=ID (the "New device on the network" alert).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSelector } from "react-redux";
import { Link, useSearchParams } from "react-router-dom";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { formatDateTime, formatWhen, relativeDays } from "../../utils/dates.js";
import { usePermission } from "../../hooks/usePermission";
import { errorText } from "../AssetGroups/groupFormat.js";
import { AssetIcon } from "../shared/AssetIcon.jsx";
import { iconLabel } from "../shared/assetIcons.js";
import "../../assets/BackupModule.css";
import "../../assets/Syslog.css";
import "../../assets/UnknownDevices.css";

const PAGE = 50;
const KIND = {
    virtual_machine: t("Virtual machine"),
    mobile: t("Phone, tablet or laptop"),
    computer: t("Computer"),
    network: t("Network device"),
    private: t("Private (random) address"),
};
const VIA = { arp: t("ARP table"), mac: t("MAC table"), both: t("ARP and MAC tables") };

const kindOf = (e) => KIND[e.guess_kind] || (e.guess_icon && e.guess_icon !== "other" ? iconLabel(e.guess_icon) : t("Unknown kind"));

const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;

// Place names that open many makers' registered names ("Hangzhou Hikvision …") say nothing about the device.
const PLACE_WORDS = new Set(["hangzhou", "zhejiang", "shenzhen", "xiamen", "beijing", "shanghai", "guangzhou", "suzhou"]);

function defaultName(e) {
    const suffix = e.mac.slice(-5).replace(":", "");
    if (e.guess_icon && e.guess_icon !== "other") return `${e.guess_icon.replace(/_/g, "-")}-${suffix}`;
    const maker = (e.vendor || "").split(/[\s,(]+/).map((w) => w.replace(/[^A-Za-z0-9-]/g, "").toLowerCase())
        .find((w) => w && !PLACE_WORDS.has(w));
    return `${maker || "device"}-${suffix}`;
}

function Banner({ data, canRead, onRead, reading, isAdmin, onSettings }) {
    if (!data.enabled) {
        return (
            <div className="bkm-note sl-banner">
                <span className="sl-banner-text">{t("Unknown device discovery is off: the ARP and MAC tables are not read.")}</span>
                {isAdmin && <button type="button" className="bkm-btn bkm-btn-sm" onClick={onSettings}>{t("Turn on")}</button>}
            </div>
        );
    }
    if (!data.sources.length) {
        return (
            <div className="bkm-note bkm-note-orange sl-banner">
                <span className="sl-banner-text">{t("No device has been read yet. Give the core routers and switches an SNMP credential (NOC → Hosts); their tables are read every {{minutes}} minutes.",
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
                {t("Reading the ARP and MAC tables of {{count}} devices every {{minutes}} minutes; last read {{when}}.",
                    { count: n(data.sources.length), minutes: n(data.interval_minutes), when: formatWhen(data.last_read_at) })}
                {failed > 0 && ` ${t("{{value}} could not be read.", { value: n(failed) })}`}
            </span>
            {canRead && <button type="button" className="bkm-btn bkm-btn-sm" disabled={reading} onClick={onRead}>{reading ? t("Reading…") : t("Read now")}</button>}
        </div>
    );
}

function AddAssetDrawer({ device, onClose, onDone }) {
    const [types, setTypes] = useState(null);
    const [form, setForm] = useState({ asset_name: defaultName(device), asset_type_id: "", hostname: "", description: "" });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        api.get("/api/asset-types/").then(({ data }) => {
            const list = Array.isArray(data) ? data : data.items || [];
            setTypes(list);
            const match = list.find((x) => x.effective_icon === device.guess_icon) || list[0];
            if (match) setForm((f) => ({ ...f, asset_type_id: String(match.id) }));
        }).catch(() => setTypes([]));
    }, [device.guess_icon]);

    const save = () => {
        setBusy(true);
        setError(null);
        api.post(`/api/noc/endpoints/${device.id}/asset`, { ...form, asset_type_id: Number(form.asset_type_id),
            hostname: form.hostname || null, description: form.description || null })
            .then(({ data }) => onDone(data.asset_id))
            .catch((e) => setError(errorText(e, t("Could not add the asset"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="ud-add-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="ud-add-title">{t("Add to the inventory")}</h2>
                        <span className="bkm-sub">{kindOf(device)}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <dl className="ud-facts">
                        <dt>{t("MAC address")}</dt><dd><Mono>{device.mac}</Mono></dd>
                        <dt>{t("IP address")}</dt><dd>{device.ip ? <Mono>{device.ip}</Mono> : "—"}</dd>
                        <dt>{t("Maker")}</dt><dd dir="auto">{device.vendor || "—"}</dd>
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
                    <p className="bkm-small bkm-muted">{t("The IP address, MAC address and maker are filled in from the network. The asset counts towards the license like any other.")}</p>
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

function IgnoreDrawer({ devices, onClose, onDone }) {
    const [note, setNote] = useState("");
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const save = () => {
        setBusy(true);
        api.post("/api/noc/endpoints/ignore", { ids: devices.map((d) => d.id), note: note.trim() || null })
            .then(onDone)
            .catch((e) => setError(errorText(e, t("Could not save"))))
            .finally(() => setBusy(false));
    };
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="ud-ign-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="ud-ign-title">{devices.length === 1 ? t("Ignore this device") : t("Ignore {{value}} devices", { value: n(devices.length) })}</h2>
                        <span className="bkm-sub">{devices.length === 1 ? <Mono>{devices[0].mac}</Mono> : null}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <p className="bkm-small">{t("An ignored device leaves the unknown list and raises no alert. It stays under Ignored, where it can be put back.")}</p>
                    <label className="alr-lbl">{t("Why (optional)")}
                        <input className="bkm-select" value={note} maxLength={255} dir="auto" autoFocus
                               placeholder={t("e.g. guest Wi-Fi, lab equipment")} onChange={(e) => setNote(e.target.value)} />
                    </label>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={save} disabled={busy}>{t("Ignore")}</button>
                </footer>
            </aside>
        </div>
    );
}

function DeviceTable({ items, status, canWrite, selected, setSelected, onAdd, onIgnore, onUnignore }) {
    const selectable = canWrite && status !== "ignored" && status !== "known";
    const open = items.filter((e) => !e.asset && e.state === "open");
    const allOn = open.length > 0 && open.every((e) => selected.has(e.id));
    const toggle = (id) => setSelected((s) => { const x = new Set(s); if (x.has(id)) x.delete(id); else x.add(id); return x; });
    return (
        <div className="bkm-table-wrap">
            <table className="bkm-table ud-table">
                <thead>
                    <tr>
                        {selectable && (
                            <th className="ud-check">
                                <input type="checkbox" aria-label={t("Select all")} checked={allOn}
                                       onChange={() => setSelected(allOn ? new Set() : new Set(open.map((e) => e.id)))} />
                            </th>
                        )}
                        <th>{t("Device")}</th><th>{t("Address")}</th><th>{t("Seen on")}</th>
                        <th>{t("First seen")}</th><th>{t("Last seen")}</th><th />
                    </tr>
                </thead>
                <tbody>
                    {items.map((e) => (
                        <tr key={e.id}>
                            {selectable && (
                                <td className="ud-check">
                                    {!e.asset && e.state === "open" && (
                                        <input type="checkbox" aria-label={t("Select")} checked={selected.has(e.id)} onChange={() => toggle(e.id)} />
                                    )}
                                </td>
                            )}
                            <td>
                                <div className="ud-device">
                                    <AssetIcon icon={e.guess_icon} size={34} />
                                    <div>
                                        <b>{kindOf(e)}</b>
                                        <span className="bkm-sub" dir="auto">{e.vendor || (e.private_mac ? t("No maker: the device hides its real address") : t("Maker not known"))}</span>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <div className="ud-addr">
                                    <Mono>{e.mac}</Mono>
                                    {e.ip ? <Mono>{e.ip}</Mono> : <span className="bkm-muted bkm-small">{t("No IP seen")}</span>}
                                    {e.other_ips.length > 0 && (
                                        <span className="bkm-small bkm-muted" title={e.other_ips.join(", ")}>
                                            {t("+{{value}} more addresses", { value: n(e.other_ips.length) })}
                                        </span>
                                    )}
                                </div>
                            </td>
                            <td>
                                {e.seen_by ? (
                                    <div className="ud-addr">
                                        <Link to={`/noc/hosts/${e.seen_by.asset_id}`} dir="auto"><b>{e.seen_by.name}</b></Link>
                                        <span className="bkm-sub">
                                            {e.seen_by.port ? <Mono>{e.seen_by.port}</Mono> : t("Port not known")}
                                            {e.seen_by.vlan ? <span className="bkm-pill bkm-pill-muted ud-vlan">{t("VLAN {{value}}", { value: n(e.seen_by.vlan) })}</span> : null}
                                        </span>
                                        <span className="bkm-small bkm-muted">{VIA[e.seen_via] || ""}</span>
                                    </div>
                                ) : "—"}
                            </td>
                            <td className="bkm-nowrap" title={formatDateTime(e.first_seen_at)}>
                                {relativeDays(e.first_seen_at)}
                                {e.is_new && <span className="bkm-pill bkm-pill-orange ud-new">{t("New")}</span>}
                            </td>
                            <td className="bkm-nowrap" title={formatDateTime(e.last_seen_at)}>{formatWhen(e.last_seen_at)}</td>
                            <td className="ud-actions">
                                {e.asset ? (
                                    <Link className="bkm-link" to={`/assets/inventory/${e.asset.id}`} dir="auto">{e.asset.name}</Link>
                                ) : e.state === "ignored" ? (
                                    <div className="ud-ignored">
                                        <span className="bkm-small" dir="auto">{e.ignore_note ? `«${e.ignore_note}»` : t("Ignored")}</span>
                                        {(e.ignored_by || e.ignored_at) && (
                                            <span className="bkm-small bkm-muted">
                                                {t("by {{user}}, {{when}}", { user: e.ignored_by || "—", when: relativeDays(e.ignored_at) })}
                                            </span>
                                        )}
                                        {canWrite && <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onUnignore(e)}>{t("Stop ignoring")}</button>}
                                    </div>
                                ) : canWrite && (
                                    <>
                                        <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" onClick={() => onAdd(e)}>{t("Add as asset")}</button>
                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onIgnore([e])}>{t("Ignore")}</button>
                                    </>
                                )}
                            </td>
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
                    <h2>{t("Devices whose tables are read")}</h2>
                    <p>{t("Every reachable device with an SNMP credential. Routers and firewalls give IP and MAC (ARP table); switches give the port each MAC is on (MAC table).")}</p>
                </div>
            </div>
            {data.sources.length === 0 ? (
                <div className="bkm-empty"><b>{t("None yet")}</b></div>
            ) : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead><tr><th>{t("Device")}</th><th>{t("Last read")}</th><th>{t("Result")}</th><th>{t("ARP entries")}</th><th>{t("MAC entries")}</th></tr></thead>
                        <tbody>
                            {data.sources.map((s) => (
                                <tr key={s.asset_id}>
                                    <td><Link to={`/noc/hosts/${s.asset_id}`} dir="auto"><b>{s.name}</b></Link></td>
                                    <td title={formatDateTime(s.last_read_at)}>{formatWhen(s.last_read_at)}</td>
                                    <td>{s.ok ? <span className="bkm-pill bkm-pill-ok">{t("Read successfully")}</span>
                                        : <span className="bkm-pill bkm-pill-bad" title={s.error || ""}>{t("Could not read")}</span>}
                                        {!s.ok && s.error && <span className="bkm-sub bkm-mono ud-err" dir="ltr">{s.error}</span>}</td>
                                    <td>{n(s.arp_entries)}</td>
                                    <td>{n(s.mac_entries)}</td>
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
    const [form, setForm] = useState({ enabled: data.enabled, interval_minutes: data.interval_minutes });
    const [msg, setMsg] = useState(null);
    const [busy, setBusy] = useState(false);
    const changed = form.enabled !== data.enabled || Number(form.interval_minutes) !== data.interval_minutes;
    const save = () => {
        setBusy(true);
        setMsg(null);
        api.put("/api/noc/endpoints/settings", { enabled: form.enabled, interval_minutes: Number(form.interval_minutes) })
            .then(() => { setMsg({ ok: true, text: t("Saved") }); onSaved(); })
            .catch((e) => setMsg({ ok: false, text: errorText(e, t("Could not save")) }))
            .finally(() => setBusy(false));
    };
    return (
        <div className="bkm-two sl-settings">
            <section className="bkm-card">
                <h2 className="bkm-h3">{t("Finding unknown devices")}</h2>
                {!isAdmin && <p className="bkm-small bkm-muted">{t("Only a system administrator can change these settings.")}</p>}
                <div className="sl-form">
                    <label className="sl-check">
                        <input type="checkbox" checked={form.enabled} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                        {t("Read the ARP and MAC tables of the monitored devices")}
                    </label>
                    <label className="alr-lbl">{t("Every (minutes)")}
                        <input className="bkm-select" type="number" min={5} max={1440} value={form.interval_minutes} disabled={!isAdmin}
                               onChange={(e) => setForm({ ...form, interval_minutes: e.target.value })} />
                    </label>
                    <p className="bkm-small bkm-muted">{t("Devices present at the first read of a router or switch are listed but raise no alert; only devices that appear later do (alert “New device on the network”).")}</p>
                    {msg && <div className={`bkm-note ${msg.ok ? "bkm-note-ok" : "bkm-note-error"}`}>{msg.text}</div>}
                    {isAdmin && <div><button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !changed} onClick={save}>{t("Save")}</button></div>}
                </div>
            </section>
            <section className="bkm-card">
                <h2 className="bkm-h3">{t("What the devices must allow")}</h2>
                <p className="bkm-small bkm-muted">{t("Read-only SNMP access to these tables (on net-snmp: the view of the community or user):")}</p>
                <div className="sl-howto">
                    <pre dir="ltr">{"IP-MIB ipNetToMediaTable      1.3.6.1.2.1.4.22\nIP-MIB ipNetToPhysicalTable   1.3.6.1.2.1.4.35\nBRIDGE-MIB / Q-BRIDGE-MIB     1.3.6.1.2.1.17\nIF-MIB ifPhysAddress          1.3.6.1.2.1.2.2.1.6"}</pre>
                </div>
                <p className="bkm-small bkm-muted">{t("Cisco IOS switches answer the MAC table per VLAN only (community@VLAN); without it the devices are still found through the routers' ARP tables, only without the switch port.")}</p>
            </section>
        </div>
    );
}

export function UnknownDevicesPage() {
    const [search, setSearch] = useSearchParams();
    const role = useSelector((s) => s.auth.role);
    const isAdmin = role === "admin";
    const canWrite = usePermission("noc", "write");
    const focus = search.get("focus");
    const tab = ["new", "ignored", "known", "sources", "settings"].includes(search.get("tab")) ? search.get("tab") : "unknown";
    const [query, setQuery] = useState("");
    const [q, setQ] = useState("");
    const [data, setData] = useState(null);
    const [items, setItems] = useState([]);
    const [page, setPage] = useState(1);
    const [error, setError] = useState(null);
    const [notice, setNotice] = useState(null);
    const [reading, setReading] = useState(false);
    const [selected, setSelected] = useState(new Set());
    const [adding, setAdding] = useState(null);
    const [ignoring, setIgnoring] = useState(null);
    const listStatus = ["sources", "settings"].includes(tab) ? "unknown" : tab;

    const load = useCallback((p = 1) => {
        const params = { status: listStatus, q: q || undefined, id: focus || undefined, page: p, page_size: PAGE };
        return api.get("/api/noc/endpoints", { params })
            .then(({ data: d }) => {
                setData(d);
                setItems((cur) => (p === 1 ? d.items : [...cur, ...d.items]));
                if (p === 1) setSelected(new Set());
                setPage(p);
                setError(null);
            })
            .catch((e) => setError(errorText(e, t("Could not load the devices"))));
    }, [listStatus, q, focus]);

    useEffect(() => { load(1); }, [load]);

    const go = (name) => {
        const p = new URLSearchParams(search);
        p.delete("focus");
        if (name === "unknown") p.delete("tab"); else p.set("tab", name);
        setSearch(p, { replace: true });
    };
    const readNow = () => {
        setReading(true);
        setNotice(null);
        api.post("/api/noc/endpoints/read-now")
            .then(({ data: r }) => {
                setNotice({ ok: true, text: t("Read {{devices}} devices: {{addresses}} addresses, {{unknown}} of them not in the inventory.",
                    { devices: n(r.devices_read), addresses: n(r.addresses), unknown: n(r.unknown) }) });
                load(1);
            })
            .catch((e) => setNotice({ ok: false, text: errorText(e, t("Could not read the devices")) }))
            .finally(() => setReading(false));
    };
    const unignore = (e) => api.post(`/api/noc/endpoints/${e.id}/unignore`).then(() => load(1))
        .catch((err) => setNotice({ ok: false, text: errorText(err, t("Could not save")) }));
    const chosen = useMemo(() => items.filter((e) => selected.has(e.id)), [items, selected]);
    const c = data?.counts;

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>{t("Unknown devices")}</h1>
                    <p>{t("Devices the monitored routers and switches see on the network that are not in the inventory. NGCorion only reads their ARP and MAC tables over SNMP; nothing is scanned.")}</p>
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {data && <Banner data={data} canRead={canWrite} onRead={readNow} reading={reading} isAdmin={isAdmin} onSettings={() => go("settings")} />}
            {notice && (
                <div className={`bkm-note ${notice.ok ? "bkm-note-ok" : "bkm-note-error"}`}>
                    {notice.text}
                    {notice.assetId && <> <Link className="bkm-link" to={`/assets/inventory/${notice.assetId}`}>{t("Open the asset")}</Link></>}
                </div>
            )}

            {c && (
                <div className="bkm-stats bkm-stats-4">
                    <div className={`bkm-stat ${c.unknown ? "bkm-stat-warn" : ""}`}>
                        <span>{t("Unknown devices")}</span>
                        <b className={c.unknown ? "bkm-orange" : ""}>{n(c.unknown)}</b>
                        <small>{t("Not in the inventory and not ignored")}</small>
                    </div>
                    <div className={`bkm-stat ${c.new ? "bkm-stat-warn" : ""}`}>
                        <span>{t("New · last 24 hours")}</span>
                        <b className={c.new ? "bkm-red" : ""}>{n(c.new)}</b>
                        <small>{t("Appeared after the first read")}</small>
                    </div>
                    <div className="bkm-stat">
                        <span>{t("In the inventory")}</span>
                        <b className="bkm-navy">{n(c.known)}</b>
                        <small>{t("Recognised by MAC or IP address")}</small>
                    </div>
                    <div className="bkm-stat">
                        <span>{t("Ignored")}</span>
                        <b>{n(c.ignored)}</b>
                        <small>{t("No alert for these")}</small>
                    </div>
                </div>
            )}

            <div className="bkm-chips" role="tablist" aria-label={t("Unknown devices")}>
                {[["unknown", t("Unknown devices"), c?.unknown], ["new", t("New"), c?.new], ["ignored", t("Ignored"), c?.ignored],
                  ["known", t("In the inventory"), c?.known], ["sources", t("Devices read")], ["settings", t("Settings")]].map(([k, label, count]) => (
                    <button key={k} type="button" role="tab" aria-selected={tab === k && !focus}
                            className={`bkm-chip ${tab === k && !focus ? "is-on" : ""}`} onClick={() => go(k)}>
                        {label}{count !== undefined && <span className="ud-count">{n(count)}</span>}
                    </button>
                ))}
            </div>

            {tab === "sources" && data && <Sources data={data} />}
            {tab === "settings" && data && <Settings key={`${data.enabled}-${data.interval_minutes}`} data={data} isAdmin={isAdmin} onSaved={() => load(1)} />}
            {!["sources", "settings"].includes(tab) && (
                <section className="bkm-card bkm-flush">
                    <div className="sl-filters">
                        {focus ? (
                            <span className="bkm-small">{t("Showing the device from the alert.")} <button type="button" className="bkm-link ud-linkbtn" onClick={() => go(tab)}>{t("Show all")}</button></span>
                        ) : (
                            <form className="bkm-search" role="search" onSubmit={(e) => { e.preventDefault(); setQ(query.trim()); }}>
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                                <input value={query} onChange={(e) => setQuery(e.target.value)} maxLength={100} dir="auto"
                                       placeholder={t("Search MAC, IP, maker or port…")} aria-label={t("Search")} />
                            </form>
                        )}
                        <span className="sl-grow" />
                        {canWrite && chosen.length > 0 && (
                            <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setIgnoring(chosen)}>
                                {t("Ignore {{value}} selected", { value: n(chosen.length) })}
                            </button>
                        )}
                    </div>
                    {data && items.length === 0 && (
                        <div className="bkm-empty">
                            <b>{tab === "unknown" ? t("No unknown device") : t("Nothing here")}</b>
                            {tab === "unknown" && <span>{t("Every address the monitored devices see belongs to an asset or is ignored.")}</span>}
                        </div>
                    )}
                    {items.length > 0 && (
                        <DeviceTable items={items} status={focus ? "all" : tab} canWrite={canWrite} selected={selected} setSelected={setSelected}
                                     onAdd={setAdding} onIgnore={setIgnoring} onUnignore={unignore} />
                    )}
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
                <AddAssetDrawer device={adding} onClose={() => setAdding(null)}
                                onDone={(assetId) => {
                                    setAdding(null);
                                    setNotice({ ok: true, text: t("Added to the inventory."), assetId });
                                    load(1);
                                }} />
            )}
            {ignoring && (
                <IgnoreDrawer devices={ignoring} onClose={() => setIgnoring(null)}
                              onDone={() => { setIgnoring(null); setSelected(new Set()); load(1); }} />
            )}
        </div>
    );
}

export default UnknownDevicesPage;
