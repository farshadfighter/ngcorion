/**
 * End of life (/assets/software/lifecycle, GET /api/eol/...): the operating systems, firmware and server
 * software the inventory found on the assets, against the end of their vendor's support - from the
 * endoflife.date catalog the installation keeps (built in, updated online or from a file) and the
 * organisation's own products - plus what was entered by hand for devices the inventory does not see.
 *
 * Views: what needs attention (unsupported, paid extended support only, ending soon), everything, the
 * software the catalog does not know, and the catalog itself (administrators update it, import a file,
 * add products of their own and set how early to warn).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useSelector } from "react-redux";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { formatDate, formatDateTime } from "../../utils/dates.js";
import { usePermission } from "../../hooks/usePermission";
import { DateInput } from "../shared/DateInput.jsx";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";
import { SoftwareTabs } from "./SoftwareTabs.jsx";
import { errorText, saveBlob } from "./softwareFormat.js";
import { EOL_STATUS, untilText } from "./eolFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Software.css";
import "../../assets/UnknownDevices.css";
import "../../assets/BenchmarkPolicy.css";
import "../../assets/Lifecycle.css";

const SOURCE = {
    builtin: t("Built in"), online: t("endoflife.date"), import: t("Imported file"), custom: t("The organisation's"),
};
const VIEWS = [["attention", t("Needs attention")], ["all", t("All")], ["unknown", t("Not in the catalog")], ["catalog", t("Catalog")]];
const ATTENTION = ["unsupported", "extended", "ending"];

const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;


function useAssets() {
    const [assets, setAssets] = useState([]);
    useEffect(() => {
        api.get("/api/assets/").then(({ data }) => setAssets(Array.isArray(data) ? data : data.items || [])).catch(() => setAssets([]));
    }, []);
    return assets;
}

// ── entered by hand ──────────────────────────────────────────────────────

function EntryDrawer({ onClose, onDone, presetAsset }) {
    const assets = useAssets();
    const [q, setQ] = useState("");
    const [form, setForm] = useState({ asset_id: presetAsset || "", name: "", version: "", support_until: "", note: "" });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const shown = useMemo(() => {
        const needle = q.trim().toLowerCase();
        return assets.filter((a) => !needle || `${a.asset_name} ${a.ip_address || ""}`.toLowerCase().includes(needle)).slice(0, 200);
    }, [assets, q]);
    const save = () => {
        setBusy(true);
        setError(null);
        api.post("/api/eol/entries", { asset_id: Number(form.asset_id), name: form.name.trim(), version: form.version.trim() || null,
            support_until: form.support_until, note: form.note.trim() || null })
            .then(onDone).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const ready = form.asset_id && form.name.trim().length >= 2 && form.support_until;
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="eol-entry-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="eol-entry-title">{t("Enter an end of support")}</h2>
                        <span className="bkm-sub">{t("For a device the inventory does not see: a camera's firmware, an appliance, a controller.")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <label className="alr-lbl">{t("Asset")}
                        <input className="bkm-select" type="search" value={q} placeholder={t("Search assets…")} onChange={(e) => setQ(e.target.value)} />
                        <select className="bkm-select eol-pick" size={6} value={form.asset_id} onChange={(e) => setForm({ ...form, asset_id: e.target.value })}>
                            {shown.map((a) => <option key={a.id} value={a.id}>{a.asset_name}{a.ip_address ? ` · ${a.ip_address}` : ""}</option>)}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Software or firmware")}
                        <input className="bkm-select" value={form.name} maxLength={200} dir="auto" onChange={(e) => setForm({ ...form, name: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Version (optional)")}
                        <input className="bkm-select" value={form.version} maxLength={80} dir="ltr" onChange={(e) => setForm({ ...form, version: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Security support until")}
                        <DateInput className="bkm-select" value={form.support_until} onChange={(v) => setForm({ ...form, support_until: v })} />
                    </label>
                    <label className="alr-lbl">{t("Note (optional)")}
                        <textarea className="bkm-select bp-reason" rows={3} value={form.note} maxLength={2000} dir="auto"
                                  placeholder={t("Where the date comes from")} onChange={(e) => setForm({ ...form, note: e.target.value })} />
                    </label>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !ready} onClick={save}>{t("Save")}</button>
                </footer>
            </aside>
        </div>
    );
}

// ── the organisation's own product ───────────────────────────────────────

function CustomDrawer({ product, presetName, onClose, onDone }) {
    const [form, setForm] = useState({
        name: product?.name || presetName || "",
        names: (product?.match_names || (presetName ? [presetName] : [])).join("\n"),
        cycles: product?.cycles?.length ? product.cycles.map((c) => ({ cycle: c.cycle, security_until: c.security_until || "",
            extended_until: c.extended_until || "" })) : [{ cycle: "", security_until: "", extended_until: "" }],
    });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const setCycle = (i, k, v) => setForm((f) => ({ ...f, cycles: f.cycles.map((c, j) => (j === i ? { ...c, [k]: v } : c)) }));
    const save = () => {
        setBusy(true);
        setError(null);
        const body = { name: form.name.trim(), match_names: form.names.split("\n").map((x) => x.trim()).filter(Boolean),
            cycles: form.cycles.filter((c) => c.cycle.trim() && c.security_until)
                .map((c) => ({ cycle: c.cycle.trim(), security_until: c.security_until, extended_until: c.extended_until || null })) };
        const req = product ? api.put(`/api/eol/catalog/custom/${product.key}`, body) : api.post("/api/eol/catalog/custom", body);
        req.then(onDone).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="eol-custom-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer eol-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="eol-custom-title">{product ? t("Edit the product") : t("Add a product of your own")}</h2>
                        <span className="bkm-sub">{t("For software or firmware endoflife.date does not track, from its vendor's announcement.")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <label className="alr-lbl">{t("Name")}
                        <input className="bkm-select" value={form.name} maxLength={120} dir="auto" onChange={(e) => setForm({ ...form, name: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Found in the inventory as (one name per line)")}
                        <textarea className="bkm-select bp-reason" rows={2} value={form.names} dir="ltr" onChange={(e) => setForm({ ...form, names: e.target.value })} />
                    </label>
                    <div className="eol-cycles">
                        <div className="eol-cycle-head">
                            <span>{t("Release cycle")}</span><span>{t("Security support until")}</span><span>{t("Extended support until")}</span><span />
                        </div>
                        {form.cycles.map((c, i) => (
                            <div key={i} className="eol-cycle-row">
                                <input className="bkm-select" value={c.cycle} dir="ltr" placeholder="20.0" aria-label={t("Release cycle")}
                                       onChange={(e) => setCycle(i, "cycle", e.target.value)} />
                                <DateInput className="bkm-select" value={c.security_until} onChange={(v) => setCycle(i, "security_until", v)} />
                                <DateInput className="bkm-select" value={c.extended_until} onChange={(v) => setCycle(i, "extended_until", v)} />
                                <button type="button" className="bkm-icon-btn" aria-label={t("Remove")} disabled={form.cycles.length === 1}
                                        onClick={() => setForm((f) => ({ ...f, cycles: f.cycles.filter((_, j) => j !== i) }))}>✕</button>
                            </div>
                        ))}
                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setForm((f) => ({ ...f, cycles: [...f.cycles, { cycle: "", security_until: "", extended_until: "" }] }))}>
                            {t("Add a release cycle")}</button>
                        <p className="bkm-small bkm-muted">{t("A version matches a release cycle by its first numbers: 20.0.1 is cycle 20.0, or 20.")}</p>
                    </div>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || form.name.trim().length < 2 || !form.names.trim()} onClick={save}>{t("Save")}</button>
                </footer>
            </aside>
        </div>
    );
}

function ProductDrawer({ productKey, isAdmin, onClose, onEdit }) {
    const [p, setP] = useState(null);
    useEffect(() => {
        api.get(`/api/eol/catalog/${encodeURIComponent(productKey)}`).then(({ data }) => setP(data)).catch(() => setP({ cycles: [] }));
    }, [productKey]);
    const d = (v) => (v === true ? t("Ended") : v ? formatDate(v) : "—");
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="eol-product-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer eol-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="eol-product-title">{p?.name || productKey}</h2>
                        {p && <span className="bkm-sub">{SOURCE[p.source]}{p.link && <> · <a href={p.link} target="_blank" rel="noreferrer">{t("Source")}</a></>}</span>}
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    {!p ? <p className="bkm-muted">{t("Loading…")}</p> : (
                        <div className="bkm-table-wrap">
                            <table className="bkm-table eol-table">
                                <thead><tr><th>{t("Release cycle")}</th><th>{t("Status")}</th><th>{t("Security support until")}</th><th>{t("Extended support until")}</th></tr></thead>
                                <tbody>
                                    {p.cycles.map((c) => (
                                        <tr key={c.cycle}>
                                            <td><Mono>{c.label || c.cycle}</Mono>{c.lts && <span className="bkm-pill bkm-pill-muted eol-lts">LTS</span>}
                                                {c.latest && <span className="bkm-small bkm-muted eol-block">{t("Latest {{version}}", { version: c.latest })}</span>}</td>
                                            <td><span className={`bkm-pill ${EOL_STATUS[c.status].pill}`}>{EOL_STATUS[c.status].label}</span></td>
                                            <td className="bkm-small">{d(c.security_until)}</td>
                                            <td className="bkm-small">{d(c.extended_until)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
                {isAdmin && p?.source === "custom" && (
                    <footer className="bkm-drawer-foot">
                        <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => onEdit(p)}>{t("Edit")}</button>
                    </footer>
                )}
            </aside>
        </div>
    );
}

function Catalog({ isAdmin, onChanged }) {
    const [data, setData] = useState(null);
    const [settings, setSettings] = useState(null);
    const [open, setOpen] = useState(null);
    const [editing, setEditing] = useState(undefined);
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState(null);
    const [error, setError] = useState(null);
    const load = useCallback(() => {
        api.get("/api/eol/catalog").then(({ data: d }) => setData(d)).catch((e) => setError(errorText(e, t("Could not load the catalog"))));
        api.get("/api/eol/settings").then(({ data: d }) => setSettings(d)).catch(() => {});
    }, []);
    useEffect(() => { load(); }, [load]);
    const done = (msg) => { setNotice(msg); setError(null); load(); onChanged(); };
    const fail = (e) => { setError(errorText(e, t("Could not save"))); setNotice(null); };
    const update = () => {
        setBusy(true);
        api.post("/api/eol/catalog/update").then(({ data: d }) => done(d.failed.length
            ? t("{{value}} products updated; {{failed}} could not be read", { value: n(d.updated), failed: n(d.failed.length) })
            : t("{{value}} products updated from endoflife.date", { value: n(d.updated) }))).catch(fail).finally(() => setBusy(false));
    };
    const importFile = (file) => {
        if (!file) return;
        const fd = new FormData();
        fd.append("file", file);
        setBusy(true);
        api.post("/api/eol/catalog/import", fd).then(({ data: d }) => done(t("{{value}} products imported", { value: n(d.imported) })))
            .catch(fail).finally(() => setBusy(false));
    };
    const exportIt = () => api.get("/api/eol/catalog/export").then(({ data: d }) =>
        saveBlob(new Blob([JSON.stringify(d, null, 1)], { type: "application/json" }), `ngcorion-eol-catalog-${new Date().toISOString().slice(0, 10)}.json`))
        .catch(fail);
    const reset = (p) => api.delete(`/api/eol/catalog/${encodeURIComponent(p.key)}`)
        .then(() => done(p.source === "custom" ? t("Product deleted") : t("Back to the built-in dates"))).catch(fail);
    const saveWarn = () => api.put("/api/eol/settings", { warn_days: Number(settings.warn_days) })
        .then(() => done(t("Saved"))).catch(fail);

    return (
        <section className="bkm-card bkm-flush">
            <div className="bkm-card-head eol-cat-head">
                <div>
                    <h2>{t("Catalog")}</h2>
                    <p>{data && t("Release cycles and support dates from endoflife.date (built-in data of {{date}}). Products updated online or from a file replace the built-in dates; products of your own cover what endoflife.date does not track.", { date: formatDate(data.generated) })}</p>
                </div>
                <div className="bkm-actions">
                    <button type="button" className="bkm-btn" onClick={exportIt}>{t("Export")}</button>
                    {isAdmin && (
                        <>
                            <label className="bkm-btn eol-file">{t("Import a file")}
                                <input type="file" accept=".json,application/json" onChange={(e) => { importFile(e.target.files?.[0]); e.target.value = ""; }} />
                            </label>
                            <button type="button" className="bkm-btn" disabled={busy} onClick={update}>{busy ? t("Updating…") : t("Update from endoflife.date")}</button>
                            <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setEditing(null)}>{t("Add a product of your own")}</button>
                        </>
                    )}
                </div>
            </div>
            {notice && <div className="bkm-note bkm-note-ok eol-pad">{notice}</div>}
            {error && <div className="bkm-note bkm-note-error eol-pad">{error}</div>}
            {settings && (
                <div className="eol-settings">
                    <label className="alr-lbl">{t("Warn before the end of support")}
                        <span className="eol-inline">
                            <input className="bkm-select" type="number" min={30} max={730} value={settings.warn_days} disabled={!isAdmin}
                                   onChange={(e) => setSettings({ ...settings, warn_days: e.target.value })} />
                            <span>{t("days")}</span>
                            {isAdmin && <button type="button" className="bkm-btn bkm-btn-sm" onClick={saveWarn}>{t("Save")}</button>}
                        </span>
                    </label>
                </div>
            )}
            {!data ? <p className="bkm-muted eol-pad">{t("Loading…")}</p> : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table eol-table">
                        <thead><tr><th>{t("Product")}</th><th>{t("Release cycles")}</th><th>{t("Source")}</th><th /></tr></thead>
                        <tbody>
                            {data.products.map((p) => (
                                <tr key={p.key}>
                                    <td><button type="button" className="bkm-link" onClick={() => setOpen(p.key)}>{p.name}</button>
                                        {p.match_names && <span className="bkm-small bkm-muted eol-block"><Mono>{p.match_names.join(", ")}</Mono></span>}</td>
                                    <td>{n(p.cycles)}</td>
                                    <td className="bkm-small">{SOURCE[p.source]}{p.updated_at && <span className="bkm-muted eol-block">{formatDateTime(p.updated_at)}</span>}</td>
                                    <td>{isAdmin && p.source !== "builtin" && (
                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => reset(p)}>
                                            {p.source === "custom" ? t("Delete") : t("Back to built-in")}</button>
                                    )}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
            {open && <ProductDrawer productKey={open} isAdmin={isAdmin} onClose={() => setOpen(null)}
                                    onEdit={(p) => { setOpen(null); setEditing({ ...p, match_names: data.products.find((x) => x.key === p.key)?.match_names }); }} />}
            {editing !== undefined && <CustomDrawer product={editing} onClose={() => setEditing(undefined)}
                                                    onDone={() => { setEditing(undefined); done(t("Saved")); }} />}
        </section>
    );
}

// ── page ─────────────────────────────────────────────────────────────────

export function LifecyclePage() {
    const canWrite = usePermission("asset_list", "write");
    const isAdmin = useSelector((s) => s.auth.role) === "admin";
    const [params, setParams] = useSearchParams();
    const assetFilter = Number(params.get("asset")) || null;
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [view, setView] = useState("attention");
    const [open, setOpen] = useState(null);
    const [entering, setEntering] = useState(false);
    const [own, setOwn] = useState(null);
    const [tick, setTick] = useState(0);
    useEffect(() => {
        api.get("/api/eol/overview").then(({ data: d }) => setData(d)).catch((e) => setError(errorText(e, t("Could not load the end-of-life view"))));
    }, [tick]);
    const refresh = () => setTick((x) => x + 1);

    const groups = useMemo(() => (data?.groups || [])
        .filter((g) => view !== "attention" || ATTENTION.includes(g.status))
        .map((g) => (assetFilter ? { ...g, assets: g.assets.filter((a) => a.id === assetFilter) } : g))
        .filter((g) => g.assets.length), [data, view, assetFilter]);
    const s = data?.summary?.assets || {};
    const filteredAsset = assetFilter && data?.groups.flatMap((g) => g.assets).find((a) => a.id === assetFilter);
    const removeEntry = (id) => api.delete(`/api/eol/entries/${id}`).then(refresh).catch((e) => setError(errorText(e, t("Could not save"))));

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <span className="bkm-crumb">{t("Asset Management")} › {t("Software")}</span>
                    <h1>{t("End of life")}</h1>
                    <p>{t("Operating systems, firmware and server software of the assets against the end of their vendor's support. Past that date no more security fixes come; an upgrade or replacement has to be planned.")}</p>
                </div>
                <div className="bkm-actions">
                    <ReportShortcut template="end_of_life" className="bkm-btn" />
                    {canWrite && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setEntering(true)}>{t("Enter an end of support")}</button>}
                </div>
            </div>
            <SoftwareTabs />
            {error && <div className="bkm-note bkm-note-error">{error}</div>}

            {data && (
                <div className="bkm-stats bkm-stats-4">
                    {[["unsupported", t("Assets with unsupported software")], ["extended", t("Only paid extended support")],
                      ["ending", t("Support ends within {{days}} days", { days: n(data.warn_days) })], ["supported", t("Supported")]].map(([k, label]) => (
                        <button key={k} type="button" className={`bkm-stat eol-stat eol-${k}`} onClick={() => setView(k === "supported" ? "all" : "attention")}>
                            <b>{n(s[k] || 0)}</b><span>{label}</span>
                        </button>
                    ))}
                </div>
            )}
            {data && data.summary.assets_with_data === 0 && (
                <div className="bkm-note bkm-note-orange">{t("No operating system or firmware is known yet: audits collect them (software inventory), or type the OS on the asset.")}</div>
            )}
            {filteredAsset && (
                <div className="bkm-note sl-banner">
                    <span className="sl-banner-text">{t("Only the asset {{name}}", { name: filteredAsset.name })}</span>
                    <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setParams({})}>{t("Show all")}</button>
                </div>
            )}

            <div className="bkm-chips" role="tablist" aria-label={t("View")}>
                {VIEWS.map(([k, label]) => (
                    <button key={k} type="button" role="tab" aria-selected={view === k}
                            className={`bkm-chip ${view === k ? "is-on" : ""}`} onClick={() => setView(k)}>
                        {label}{k === "unknown" && data?.unknown.length ? <span className="ud-count">{n(data.unknown.length)}</span> : null}
                    </button>
                ))}
            </div>

            {(view === "attention" || view === "all") && data && (
                <section className="bkm-card bkm-flush">
                    {groups.length === 0 ? (
                        <div className="bkm-empty"><b>{view === "attention" ? t("Nothing needs attention") : t("Nothing here")}</b>
                            {view === "attention" && <span>{t("No software of the assets is past or near the end of its vendor's support.")}</span>}</div>
                    ) : (
                        <div className="bkm-table-wrap">
                            <table className="bkm-table eol-table">
                                <thead><tr><th>{t("Software")}</th><th>{t("Status")}</th><th>{t("Assets")}</th></tr></thead>
                                <tbody>
                                    {groups.map((g) => [
                                        <tr key={g.key}>
                                            <td>
                                                <div className="ud-addr">
                                                    <b dir="auto">{g.title}</b>
                                                    {g.manual && <span className="bkm-small bkm-muted">{t("Entered by hand")}</span>}
                                                    {g.latest && <span className="bkm-small bkm-muted">{t("Latest {{version}}", { version: g.latest })}</span>}
                                                </div>
                                            </td>
                                            <td>
                                                <div className="bp-stack">
                                                    <span className={`bkm-pill ${EOL_STATUS[g.status].pill}`}>{EOL_STATUS[g.status].label}</span>
                                                    <span className="bkm-small">{untilText(g)}</span>
                                                    {g.status === "extended" && g.ended_on && <span className="bkm-small bkm-muted">{t("Standard support ended {{date}}", { date: formatDate(g.ended_on) })}</span>}
                                                    {g.security_only && g.status !== "unsupported" && <span className="bkm-small bkm-muted">{t("Security fixes only")}</span>}
                                                </div>
                                            </td>
                                            <td><button type="button" className="bkm-link" onClick={() => setOpen(open === g.key ? null : g.key)}>
                                                {t("{{value}} assets", { value: n(g.assets.length) })}</button></td>
                                        </tr>,
                                        open === g.key && (
                                            <tr key={`${g.key}-a`} className="eol-sub"><td colSpan={3}>
                                                <ul className="eol-assets">
                                                    {g.assets.map((a) => (
                                                        <li key={`${a.id}-${a.entry_id || a.version}`}>
                                                            <Link to={`/assets/inventory/${a.id}`}><bdi>{a.name}</bdi></Link>
                                                            <span className="bkm-small bkm-muted">{a.ip && <Mono>{a.ip}</Mono>}{a.version && <> · <Mono>{a.version}</Mono></>}</span>
                                                            {a.entry_id && canWrite && <button type="button" className="bkm-link" onClick={() => removeEntry(a.entry_id)}>{t("Remove")}</button>}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </td></tr>
                                        ),
                                    ])}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>
            )}

            {view === "unknown" && data && (
                <section className="bkm-card bkm-flush">
                    <div className="bkm-card-head">
                        <div>
                            <h2>{t("Not in the catalog")}</h2>
                            <p>{t("Software found on the assets whose product or release cycle the catalog does not know. Add it as a product of your own, or enter its end of support on the asset.")}</p>
                        </div>
                    </div>
                    {data.unknown.length === 0 ? <div className="bkm-empty"><b>{t("All software found is in the catalog")}</b></div> : (
                        <div className="bkm-table-wrap">
                            <table className="bkm-table eol-table">
                                <thead><tr><th>{t("Software")}</th><th>{t("Versions")}</th><th>{t("Assets")}</th><th /></tr></thead>
                                <tbody>
                                    {data.unknown.map((u) => (
                                        <tr key={`${u.name}|${u.product_name}`}>
                                            <td><bdi dir="auto">{u.name}</bdi>{u.product_name && <span className="bkm-small bkm-muted eol-block">{t("{{product}}: release cycle not in the catalog", { product: u.product_name })}</span>}</td>
                                            <td><Mono>{u.versions.join(", ") || "—"}</Mono></td>
                                            <td>{n(u.assets)}</td>
                                            <td>{isAdmin && !u.product_name && <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setOwn(u.name)}>{t("Add as a product")}</button>}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>
            )}

            {view === "catalog" && <Catalog isAdmin={isAdmin} onChanged={refresh} />}

            {entering && <EntryDrawer presetAsset={assetFilter} onClose={() => setEntering(false)} onDone={() => { setEntering(false); refresh(); }} />}
            {own && <CustomDrawer presetName={own} onClose={() => setOwn(null)} onDone={() => { setOwn(null); refresh(); }} />}
        </div>
    );
}

