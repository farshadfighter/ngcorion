import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useSelector } from "react-redux";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { currentLanguage, t, n } from "../../i18n";
import { formatDateTime } from "../../utils/dates.js";
import { AssetSoftwareDrawer, CveCell } from "./AssetSoftwareDrawer.jsx";
import { CollectForm } from "./CollectForm.jsx";
import { MapModal } from "./MapModal.jsx";
import { SEVERITY, SOURCE, SOURCE_ORDER, count, errorText, saveBlob } from "./softwareFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Remediation.css";
import "../../assets/Software.css";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";

const VIEWS = [
    ["all", t("All")],
    ["outside_distro", t("Outside the distribution repository")],
    ["distro", t("From the distribution repository")],
    ["windows", t("Windows programs")],
    ["vulnerable", t("With vulnerabilities")],
    ["multi_version", t("Several versions")],
    ["unidentified", t("Unidentified")],
];
const PAGE = 60;
const OUTSIDE = ["third_party", "manual", "service", "firmware"];

const matchView = (r, view) => {
    switch (view) {
        case "outside_distro": return r.sources.some((s) => OUTSIDE.includes(s));
        case "distro": return r.sources.includes("distro");
        case "windows": return r.sources.includes("windows");
        case "vulnerable": return !!r.cve;
        case "multi_version": return r.versions.length > 1;
        case "unidentified": return r.status === "unknown";
        default: return true;
    }
};

const numeric = (a, b) => a.localeCompare(b, "en", { numeric: true });

/** The fleet's installed software, from the last collection of every asset. */
export function SoftwarePage() {
    const canWrite = usePermission("asset_list", "write");
    const { role } = useSelector((state) => state.auth);
    const canMap = role === "admin" || role === "manager";
    const [params, setParams] = useSearchParams();
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [reload, setReload] = useState(0);
    const [view, setView] = useState("all");
    const [search, setSearch] = useState("");
    const [limit, setLimit] = useState(PAGE);
    const [product, setProduct] = useState(null);
    const [mapping, setMapping] = useState(null);
    const [collect, setCollect] = useState(false);
    const [justCollected, setJustCollected] = useState(null);
    const [exporting, setExporting] = useState(false);
    const refresh = useCallback(() => setReload((x) => x + 1), []);
    const assetId = Number(params.get("asset")) || null;

    useEffect(() => {
        let alive = true;
        api.get("/api/software/products")
            .then(({ data: d }) => { if (alive) { setData(d); setError(null); } })
            .catch((e) => alive && setError(errorText(e, t("Could not load the software list"))));
        return () => { alive = false; };
    }, [reload]);

    const rows = useMemo(() => {
        const q = search.trim().toLowerCase();
        return (data?.items || []).filter((r) => matchView(r, view)
            && (!q || [r.label, r.publisher, ...r.names, ...r.cpes, ...r.origins].some((v) => v && v.toLowerCase().includes(q))));
    }, [data, view, search]);

    const exportExcel = () => {
        setExporting(true);
        api.get("/api/software/products/export", { params: { lang: currentLanguage() }, responseType: "blob" })
            .then((res) => saveBlob(res.data, `software-${new Date().toISOString().slice(0, 10)}.xlsx`))
            .catch(() => setError(t("Could not export the list")))
            .finally(() => setExporting(false));
    };

    const openAsset = (id) => setParams(id ? { asset: String(id) } : {});
    const s = data?.summary || {};
    const coverage = s.assets_total ? Math.round((100 * s.assets_with_inventory) / s.assets_total) : 0;

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <span className="bkm-crumb">{t("Asset Management")} › {t("Software")}</span>
                    <h1>{t("Installed Software")}</h1>
                    <p>{t("What is actually installed on each asset, from its latest collection. Every Linux and Windows audit refreshes the list; Apache, MongoDB, SQL Server, Cisco and Fortinet audits record the exact version of the product itself.")}</p>
                </div>
                <div className="bkm-actions">
                    <ReportShortcut template="software" className="bkm-btn" />
                    <button type="button" className="bkm-btn" onClick={exportExcel} disabled={exporting || !data?.items.length}>
                        {exporting ? t("Exporting…") : t("Export to Excel")}
                    </button>
                    {canWrite && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setCollect(true)}>{t("Collect now…")}</button>}
                </div>
            </div>

            <div className="bkm-stats bkm-stats-4">
                <div className="bkm-stat">
                    <b>{t("{{done}} of {{total}}", { done: n(s.assets_with_inventory ?? 0), total: n(s.assets_total ?? 0) })}</b>
                    <span>{t("Assets with a software list")}</span>
                    <div className="bkm-meter"><span style={{ width: `${coverage}%` }} /></div>
                    {s.last_collected_at && <span className="bkm-sub">{t("Latest collection {{date}}", { date: formatDateTime(s.last_collected_at) })}</span>}
                </div>
                <div className="bkm-stat">
                    <b>{count(s.outside_distro)}</b>
                    <span>{t("Products outside the distribution repository · {{count}} installed packages in total", { count: s.packages ?? 0 })}</span>
                </div>
                <div className={`bkm-stat ${s.kev_products ? "alr-stat-critical" : ""}`}>
                    <b className={s.vulnerable_products ? "bkm-red" : ""}>{count(s.vulnerable_products)}</b>
                    <span>{s.kev_products
                        ? t("Products with known vulnerabilities · {{findings}} findings, {{kev}} exploited", { findings: s.findings ?? 0, kev: s.kev_products })
                        : t("Products with known vulnerabilities · {{findings}} findings", { findings: s.findings ?? 0 })}</span>
                </div>
                <div className="bkm-stat">
                    <b className={s.unidentified ? "bkm-orange" : ""}>{count(s.unidentified)}</b>
                    <span>{t("Unidentified products · need their CPE")}</span>
                </div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={t("Filter software")}>
                    {VIEWS.map(([value, label]) => (
                        <button key={value} type="button" aria-pressed={view === value}
                                className={`bkm-chip ${view === value ? "is-on" : ""}`}
                                onClick={() => { setView(value); setLimit(PAGE); }}>
                            {label}{data ? <b>{count(data.counts[value])}</b> : null}
                        </button>
                    ))}
                </div>
                <label className="bkm-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={search} onChange={(e) => { setSearch(e.target.value); setLimit(PAGE); }}
                           placeholder={t("Search software, publisher or repository…")} aria-label={t("Search software")} />
                </label>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table sw-table sw-products">
                        <thead>
                            <tr>
                                <th style={{ width: "21%" }}>{t("Software")}</th>
                                <th style={{ width: "15%" }}>{t("Installed from")}</th>
                                <th style={{ width: "24%" }}>{t("Versions in use")}</th>
                                <th style={{ width: "6%" }}>{t("Assets")}</th>
                                <th style={{ width: "15%" }}>{t("CPE")}</th>
                                <th style={{ width: "19%" }}>{t("Vulnerabilities")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows.slice(0, limit).map((r) => (
                                <ProductRow key={`${r.status}:${r.key}:${r.label}`} r={r} canMap={canMap} advisories={!!s.advisories_loaded}
                                            onOpen={() => setProduct(r)} onMap={() => setMapping(r)} />
                            ))}
                            {data && rows.length === 0 && (
                                <tr><td colSpan={6}>
                                    <div className="bkm-empty">
                                        <b>{data.items.length ? t("No software matches these filters") : t("No software list yet")}</b>
                                        <span>{t("Software lists appear after Linux or Windows audits, or a collection on demand.")}</span>
                                    </div>
                                </td></tr>
                            )}
                            {!data && !error && <tr><td colSpan={6} className="bkm-muted">{t("Loading…")}</td></tr>}
                        </tbody>
                    </table>
                </div>
                {rows.length > limit && (
                    <div className="bkm-card-foot bkm-row-between">
                        <span>{t("{{shown}} of {{total}}", { shown: n(limit), total: n(rows.length) })}</span>
                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setLimit(limit + PAGE)}>{t("Show more")}</button>
                    </div>
                )}
            </section>

            <div className="sw-legend">
                {SOURCE_ORDER.filter((k) => k !== "firmware").map((k) => (
                    <span key={k} className={`sw-src ${SOURCE[k].cls}`}>{k === "service" ? t("Read by the product's own audit") : SOURCE[k].label}</span>
                ))}
            </div>
            <p className="alr-hint sw-note">
                {t("Packages from the distribution's own repository are matched against the distribution's own security advisories (Ubuntu USN, Debian DSA/DLA, Red Hat RHSA, Rocky RLSA, AlmaLinux ALSA), not NVD: the distributions patch security fixes into the same version number (a patched OpenSSL 3.0.2 still says 3.0.2), so comparing versions with NVD would report hundreds of false findings.")}
            </p>

            {product && <ProductDrawer product={product} canMap={canMap} onClose={() => setProduct(null)}
                                       onMap={() => setMapping(product)} onAsset={(id) => { setProduct(null); openAsset(id); }} />}
            {mapping && <MapModal product={mapping} onClose={() => setMapping(null)}
                                  onSaved={() => { setMapping(null); setProduct(null); refresh(); }} />}
            {collect && <CollectModal onClose={() => setCollect(false)} onDone={(id, col) => { setCollect(false); setJustCollected(col); refresh(); openAsset(id); }} />}
            {assetId && <AssetSoftwareDrawer key={assetId} assetId={assetId} canWrite={canWrite} canMap={canMap}
                                             justCollected={justCollected?.asset_id === assetId ? justCollected : null}
                                             onClose={() => { setJustCollected(null); openAsset(null); }} onChanged={refresh} />}
        </div>
    );
}

function Versions({ versions, max = 3 }) {
    const newest = versions.length > 1 ? versions.map((v) => v.version || "").sort(numeric).at(-1) : null;
    return (
        <span className="sw-versions">
            {versions.slice(0, max).map((v) => (
                <span key={v.version || "?"} className="sw-ver-wrap">
                    <span className={`sw-ver ${newest && v.version !== newest ? "is-old" : ""}`} title={v.version || undefined}>{v.version || "?"}</span>
                    <span className="sw-times">×{n(v.assets)}</span>
                </span>
            ))}
            {versions.length > max && <span className="bkm-muted bkm-small">{t("+{{count}} more", { count: versions.length - max })}</span>}
        </span>
    );
}

function ProductRow({ r, canMap, onOpen, onMap, advisories }) {
    const outside = r.sources.filter((s) => s !== "distro");
    const sources = outside.length ? outside : r.sources;
    return (
        <tr className="bkm-row-click" onClick={onOpen} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onOpen()}>
            <td>
                <b className="sw-name">{r.label}</b>
                <span className="bkm-sub sw-clip sw-ltr-inline" title={r.names.join(", ")}>
                    {r.publisher && r.sources.includes("windows") ? r.publisher : r.names.slice(0, 3).join(" · ")}
                    {r.name_count > 3 ? ` +${n(r.name_count - 3)}` : ""}
                </span>
            </td>
            <td>
                {sources.map((src) => (
                    <span key={src} className={`sw-src ${SOURCE[src]?.cls || ""}`}>{SOURCE[src]?.label || src}</span>
                ))}
                {r.origins.length > 0 && <span className="bkm-sub sw-ltr-inline sw-clip">{r.origins.join(", ")}</span>}
            </td>
            <td><Versions versions={r.versions} /></td>
            <td>{n(r.asset_count)}</td>
            <td onClick={(e) => e.stopPropagation()}>
                {r.status === "known" && <span className="sw-cpe">{r.cpes.join(" ")}</span>}
                {r.status === "known" && r.mapped_by === "admin" && <span className="bkm-sub">{t("set by an administrator")}</span>}
                {r.status === "internal" && <span className="bkm-pill bkm-pill-muted">{t("Internal software")}</span>}
                {r.status === "distro" && <span className="bkm-muted bkm-small">{t("Distribution package")}</span>}
                {r.status === "unknown" && (
                    <span className="sw-unknown">
                        <span className="bkm-pill bkm-pill-amber">{t("Unidentified")}</span>
                        {canMap && <button type="button" className="bkm-btn bkm-btn-sm" onClick={onMap}>{t("Identify…")}</button>}
                    </span>
                )}
            </td>
            <td>{r.status === "unknown" ? <span className="bkm-muted">{t("Unknown")}</span>
                : <CveCell item={{ ...r, source: r.sources.find((x) => x !== "distro") || "distro" }} distro={advisories ? "ok" : null} />}</td>
        </tr>
    );
}

function ProductDrawer({ product: p, canMap, onClose, onMap, onAsset }) {
    const [assets, setAssets] = useState(null);
    useEffect(() => {
        let alive = true;
        api.get("/api/software/products/assets", { params: { key: p.key, status: p.status, label: p.label } })
            .then(({ data }) => alive && setAssets(data))
            .catch(() => alive && setAssets([]));
        return () => { alive = false; };
    }, [p]);
    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose]);
    const sev = p.cve && SEVERITY[p.cve.severity];
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="sw-prod-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer sw-drawer sw-drawer-narrow">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="sw-prod-title" dir="auto">{p.label}</h2>
                        <span className="bkm-sub">{p.sources.map((s) => SOURCE[s]?.label || s).join(" · ")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label={t("Close")} onClick={onClose}>×</button>
                </header>
                <div className="bkm-drawer-body">
                    <section className="rem-sec">
                        <div className="bkm-kv"><span>{t("CPE")}</span><b>{p.cpes.length ? <span className="sw-cpe">{p.cpes.join(" ")}</span>
                            : p.status === "internal" ? t("Internal software") : p.status === "distro" ? t("Distribution package") : t("Unidentified")}</b></div>
                        {p.publisher && <div className="bkm-kv"><span>{t("Publisher")}</span><b className="bidi-auto">{p.publisher}</b></div>}
                        <div className="bkm-kv"><span>{t("Package names")}</span><b className="sw-ltr-inline">{p.names.join(", ")}{p.name_count > p.names.length ? ` +${n(p.name_count - p.names.length)}` : ""}</b></div>
                        {p.origins.length > 0 && <div className="bkm-kv"><span>{t("Repository")}</span><b className="sw-ltr-inline">{p.origins.join(", ")}</b></div>}
                        <div className="bkm-kv"><span>{t("Versions in use")}</span><b><Versions versions={p.versions} max={8} /></b></div>
                        {p.cve && (
                            <div className="bkm-kv"><span>{t("Vulnerabilities")}</span><b>
                                <span className={`sw-sev ${sev?.cls || ""}`}>{t("{{count}} CVEs", { count: p.cve.count })} · {sev?.label}</span>
                                {p.cve.kev && <span className="sw-kev">KEV</span>}
                                {p.cve.affected_versions?.length > 0 && <span className="bkm-sub">{t("affected versions")}: <span className="sw-ltr-inline">{p.cve.affected_versions.join(", ")}</span></span>}
                                {p.cve.fixed_in?.length > 0 && <span className="bkm-sub">{t("fixed in")} <span className="sw-ltr-inline">{p.cve.fixed_in.join(", ")}</span></span>}
                            </b></div>
                        )}
                        {p.status === "unknown" && canMap && <button type="button" className="bkm-btn bkm-btn-primary" onClick={onMap}>{t("Identify…")}</button>}
                    </section>
                    <section className="rem-sec">
                        <h3 className="bkm-h3">{t("Assets")}</h3>
                        {!assets && <span className="bkm-muted">{t("Loading…")}</span>}
                        {assets?.map((a) => (
                            <button key={a.asset_id} type="button" className="sw-asset-line" onClick={() => onAsset(a.asset_id)}>
                                <span><b>{a.asset_name}</b>{a.ip_address && <span className="bkm-sub bkm-mono">{a.ip_address}</span>}</span>
                                <span className="sw-asset-vers">
                                    {[...new Set(a.items.map((i) => i.version || "?"))].slice(0, 2).map((v) => <span key={v} className="sw-ver">{v}</span>)}
                                </span>
                            </button>
                        ))}
                    </section>
                </div>
            </aside>
        </div>
    );
}

function CollectModal({ onClose, onDone }) {
    const [assets, setAssets] = useState(null);
    const [assetId, setAssetId] = useState("");
    useEffect(() => {
        api.get("/api/assets/").then(({ data }) => setAssets(data.filter((a) => a.ip_address))).catch(() => setAssets([]));
    }, []);
    const asset = assets?.find((a) => String(a.id) === assetId);
    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="sw-collect-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal sw-modal">
                <h2 id="sw-collect-title">{t("Collect now")}</h2>
                <p className="alr-hint">{t("Reads only the software list, without a full audit.")}</p>
                <label className="alr-lbl">{t("Asset")}
                    <select className="bkm-select" value={assetId} onChange={(e) => setAssetId(e.target.value)} autoFocus>
                        <option value="">{assets ? t("Choose an asset") : t("Loading…")}</option>
                        {(assets || []).map((a) => <option key={a.id} value={a.id}>{a.asset_name} · {a.ip_address}{a.os_name ? ` · ${a.os_name}` : ""}</option>)}
                    </select>
                </label>
                {asset ? <CollectForm key={asset.id} asset={asset} onDone={(col) => onDone(asset.id, { ...col, asset_id: asset.id })} onCancel={onClose} />
                    : <div className="alr-modal-foot"><button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button></div>}
            </div>
        </div>
    );
}
