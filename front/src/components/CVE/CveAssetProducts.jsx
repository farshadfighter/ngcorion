import { useEffect, useMemo, useRef, useState } from "react";
import api from "../../config/api.js";
import { AssetIcon } from "../shared/AssetIcon.jsx";
import { num } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";
import { t as tr } from "../../i18n";

const PAGE = 50;
const pretty = (s) => (s || "").replace(/_/g, " ");

/** "By asset": what each asset runs, as matched against the CVE database,
 *  and adding the software its own fields do not describe. */
export function CveAssetProducts({ assets, search, canWrite, onChanged }) {
    const [onlyMissing, setOnlyMissing] = useState(false);
    const [limit, setLimit] = useState(PAGE);
    const [openId, setOpenId] = useState(null);

    const rows = useMemo(() => {
        let r = assets;
        if (onlyMissing) r = r.filter((a) => !a.products.length);
        if (search) {
            r = r.filter((a) => [a.asset_name, a.ip_address, ...a.products.map((p) => `${p.label} ${p.product} ${p.version || ""}`)]
                .some((v) => v && v.toLowerCase().includes(search)));
        }
        return [...r].sort((a, b) => b.findings - a.findings || (b.products.length > 0) - (a.products.length > 0)
            || (a.asset_name || "").localeCompare(b.asset_name || ""));
    }, [assets, search, onlyMissing]);

    const missing = assets.filter((a) => !a.products.length).length;

    return (
        <div className="cvx-col">
            <div className="cvx-assets-bar">
                <span className="cvx-muted cvx-small">
                    {tr("Products are read from each asset's OS, version and model. Add software the inventory does not describe (web servers, databases, agents).")}
                </span>
                {missing > 0 && (
                    <label className="cvx-check cvx-small">
                        <input type="checkbox" checked={onlyMissing} onChange={(e) => setOnlyMissing(e.target.checked)} />
                        {tr("Only assets with no recognised product ({{num}})", { num: num(missing) })}
                    </label>
                )}
            </div>
            {!rows.length && <div className="cvx-card cvx-empty"><b>{tr("No assets match")}</b></div>}
            {rows.length > 0 && (
                <div className="cvx-card cvx-card-flush">
                    {rows.slice(0, limit).map((a) => (
                        <AssetRow key={a.asset_id} asset={a} canWrite={canWrite} open={openId === a.asset_id}
                                  onToggle={() => setOpenId(openId === a.asset_id ? null : a.asset_id)} onChanged={onChanged} />
                    ))}
                </div>
            )}
            {rows.length > limit && (
                <div className="cvx-more">
                    <button type="button" className="cvx-btn" onClick={() => setLimit(limit + PAGE)}>{tr("Show more ({{num}} left)", { num: num(rows.length - limit) })}</button>
                </div>
            )}
        </div>
    );
}

function AssetRow({ asset, canWrite, open, onToggle, onChanged }) {
    const [error, setError] = useState(null);

    const remove = async (p) => {
        setError(null);
        try {
            await api.delete(`/api/cve/assets/${asset.asset_id}/software/${p.software_id}`);
            onChanged();
        } catch (err) {
            setError(err.response?.data?.detail || tr("Could not remove"));
        }
    };

    return (
        <div className="cvx-asset-row">
            <div className="cvx-asset-main">
                <span className="cvx-asset">
                    <AssetIcon icon={asset.asset_icon} size={32} />
                    <span><b>{asset.asset_name}</b>{asset.ip_address && <span className="cvx-sub cvx-mono">{asset.ip_address}</span>}</span>
                </span>
                <div className="cvx-chips">
                    {asset.products.length === 0 && <span className="cvx-muted cvx-small">{tr("No recognised product")}</span>}
                    {asset.products.map((p) => (
                        <span key={`${p.vendor}:${p.product}:${p.version}`} className={`cvx-chip ${p.source === "manual" ? "is-manual" : ""}`}
                              title={`${p.vendor}:${p.product} · ${p.source === "manual" ? "added by hand" : "detected from the asset's fields"}`}>
                            {p.label}
                            <span className="cvx-mono">{p.version || tr("version unknown")}</span>
                            {p.source === "manual" && canWrite && (
                                <button type="button" className="cvx-chip-x" aria-label={tr("Remove {{label}}", { label: p.label })} onClick={() => remove(p)}>
                                    <Icon name="x" size={12} width={2.4} />
                                </button>
                            )}
                        </span>
                    ))}
                </div>
                <span className={`cvx-pill ${asset.findings ? "cvx-pill-bad" : "cvx-pill-muted"}`}>
                    {asset.findings ? tr("{{count}} findings", { count: asset.findings }) : tr("No findings")}
                </span>
                {canWrite && (
                    <button type="button" className="cvx-btn cvx-btn-sm" onClick={onToggle} aria-expanded={open}>
                        <Icon name="plus" size={14} /> {" "}{tr("Software")}
                    </button>
                )}
            </div>
            {asset.products.some((p) => !p.version) && (
                <div className="cvx-hint cvx-indent">{tr("A product without a version is only matched against CVEs that affect every version. Set the version on the asset to get exact matches.")}</div>
            )}
            {error && <div className="cvx-note cvx-note-error cvx-indent">{error}</div>}
            {open && <AddSoftware assetId={asset.asset_id} onDone={() => { onToggle(); onChanged(); }} onCancel={onToggle} />}
        </div>
    );
}

function AddSoftware({ assetId, onDone, onCancel }) {
    const [query, setQuery] = useState("");
    const [picked, setPicked] = useState(null);
    const [suggestions, setSuggestions] = useState([]);
    const [version, setVersion] = useState("");
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    const versionRef = useRef(null);

    useEffect(() => {
        if (picked || query.trim().length < 2) return undefined;
        let alive = true;
        const t = setTimeout(() => {
            api.get("/api/cve/products", { params: { q: query.trim() } })
                .then(({ data }) => alive && setSuggestions(data))
                .catch(() => alive && setSuggestions([]));
        }, 250);
        return () => { alive = false; clearTimeout(t); };
    }, [query, picked]);

    const choose = (s) => {
        setPicked(s);
        setQuery(`${pretty(s.vendor)} ${pretty(s.product)}`);
        setSuggestions([]);
        setTimeout(() => versionRef.current?.focus(), 0);
    };

    const save = async (e) => {
        e.preventDefault();
        setSaving(true);
        setError(null);
        try {
            await api.post(`/api/cve/assets/${assetId}/software`, { vendor: picked.vendor, product: picked.product, version: version.trim() });
            onDone();
        } catch (err) {
            const d = err.response?.data?.detail;
            setError(Array.isArray(d) ? d[0]?.msg : d || tr("Could not add"));
            setSaving(false);
        }
    };

    return (
        <form className="cvx-add-sw" onSubmit={save}>
            <div className="cvx-ac">
                <label className="cvx-field">
                    <span>{tr("Product")}</span>
                    <input className="cvx-input" placeholder={tr("Search, e.g. openssh, http server, mysql")} value={query} autoFocus
                           onChange={(e) => { setQuery(e.target.value); setPicked(null); }} />
                </label>
                {!picked && suggestions.length > 0 && (
                    <ul className="cvx-ac-list" role="listbox" aria-label={tr("Products")}>
                        {suggestions.map((s) => (
                            <li key={`${s.vendor}:${s.product}`}>
                                <button type="button" onClick={() => choose(s)}>
                                    <span><b>{pretty(s.product)}</b> <span className="cvx-muted">{pretty(s.vendor)}</span></span>
                                    <span className="cvx-muted cvx-small">{tr("{{num}} CVEs", { num: num(s.cves) })}</span>
                                </button>
                            </li>
                        ))}
                    </ul>
                )}
                {!picked && query.trim().length >= 2 && suggestions.length === 0 && (
                    <div className="cvx-hint">{tr("No product with that name in the CVE database.")}</div>
                )}
            </div>
            <label className="cvx-field cvx-field-sm">
                <span>{tr("Version")}</span>
                <input ref={versionRef} className="cvx-input cvx-mono" placeholder="e.g. 2.4.52" value={version} maxLength={80}
                       onChange={(e) => setVersion(e.target.value)} />
            </label>
            <div className="cvx-add-actions">
                <button type="submit" className="cvx-btn cvx-btn-primary cvx-btn-sm" disabled={!picked || !version.trim() || saving}>{tr("Add")}</button>
                <button type="button" className="cvx-btn cvx-btn-sm" onClick={onCancel}>{tr("Cancel")}</button>
            </div>
            {error && <div className="cvx-note cvx-note-error cvx-full">{String(error)}</div>}
        </form>
    );
}
