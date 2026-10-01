import { useEffect, useMemo, useState } from "react";
import api from "../../config/api.js";
import AssetIcon from "./AssetIcon.jsx";
import "../../assets/TargetPicker.css";

/**
 * "What do you want to audit / harden, and on which asset?"
 *
 * Shared by the Auditing and Hardening forms. The list of targets comes from
 * the server (GET /api/targets/catalog, app/core/target_catalog.py), so a new
 * audit/hardening module shows up here without frontend changes.
 *
 *   1. a target - from the categories rail, a search, or "In my inventory"
 *      (default: what this inventory actually has, most assets first)
 *   2. a version, when the target has them (linux-ubuntu-22, mssql-2019, ...)
 *   3. an asset - assets on the chosen version first; others stay selectable
 *
 * Controlled: `deviceType` / `assetId` live in the parent form, changes go out
 * through onChange(patch, asset). `patch` holds device_type and/or asset_id;
 * `asset` is the chosen asset object (or null).
 */

// Category colours (presentation only - the server sends ids and labels).
const CATEGORY_COLORS = {
    network: "#1d4ed8",
    servers: "#334155",
    platforms: "#0e7490",
    databases: "#6d28d9",
    web: "#7c3aed",
    services: "#be185d",
};
const INVENTORY = "inventory";
const ALL = "all";
const VERB = { audit: "auditing", hardening: "hardening" };

const errorText = (e) => {
    const d = e?.response?.data?.detail;
    return typeof d === "string" ? d : "Could not load the list of supported targets.";
};

// The version with the most assets, so the common case needs no extra click.
const preferredDeviceType = (t) => {
    if (!t.versions.length) return t.device_type;
    return t.versions.reduce((best, v) => (v.asset_count > best.asset_count ? v : best), t.versions[0]).device_type;
};

const targetHas = (t, dt) => t.device_type === dt || t.versions.some((v) => v.device_type === dt);

export function TargetPicker({ mode = "audit", deviceType, assetId, onChange, errors = {} }) {
    const [catalog, setCatalog] = useState(null);
    const [loadError, setLoadError] = useState(null);
    const [query, setQuery] = useState("");
    const [category, setCategory] = useState(null); // null = default view
    const [assets, setAssets] = useState([]);
    const [assetsFor, setAssetsFor] = useState(null);
    const [assetQuery, setAssetQuery] = useState("");
    const [showOther, setShowOther] = useState(false);

    useEffect(() => {
        let cancelled = false;
        api.get(`/api/targets/catalog?mode=${mode}`)
            .then((res) => {
                if (cancelled) return;
                setCatalog(res.data);
                // Nothing chosen yet: start on the target this inventory has most of.
                if (!deviceType) {
                    const targets = res.data.targets || [];
                    const first = [...targets].sort((a, b) => b.asset_count - a.asset_count)[0];
                    if (first) onChange({ device_type: preferredDeviceType(first), asset_id: "" }, null);
                }
            })
            .catch((e) => { if (!cancelled) setLoadError(errorText(e)); });
        return () => { cancelled = true; };
        // Loaded once per mode; deviceType/onChange only seed the first pick.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [mode]);

    // Assets for the chosen family (the backend filters by device type and
    // keeps unknown-type assets, which go under "Other / unknown type").
    useEffect(() => {
        if (!deviceType) return undefined;
        let cancelled = false;
        api.get(`/api/assets/?device_type=${encodeURIComponent(deviceType)}`)
            .then((res) => { if (!cancelled) { setAssets(res.data || []); setAssetsFor(deviceType); } })
            .catch(() => { if (!cancelled) { setAssets([]); setAssetsFor(deviceType); } });
        return () => { cancelled = true; };
    }, [deviceType]);

    const targets = useMemo(() => catalog?.targets || [], [catalog]);
    const selected = targets.find((t) => targetHas(t, deviceType)) || null;
    const version = selected?.versions.find((v) => v.device_type === deviceType) || null;
    const inventoryTargets = useMemo(
        () => targets.filter((t) => t.asset_count > 0).sort((a, b) => b.asset_count - a.asset_count),
        [targets]
    );
    const view = category || (inventoryTargets.length ? INVENTORY : ALL);
    const categoryLabel = (id) => catalog?.categories.find((c) => c.id === id)?.label || id;

    const q = query.trim().toLowerCase();
    const shown = useMemo(() => {
        if (q) {
            // Word-start match: "sql" finds SQL Server, not MongoDB's "nosql".
            const terms = q.split(/\s+/);
            return targets.filter((t) => {
                const words = [t.label, t.description, categoryLabel(t.category), ...t.keywords]
                    .join(" ").toLowerCase().split(/[^a-z0-9.]+/);
                return terms.every((term) => words.some((w) => w.startsWith(term)));
            });
        }
        if (view === INVENTORY) return inventoryTargets;
        if (view === ALL) return targets;
        return targets.filter((t) => t.category === view);
        // categoryLabel only reads catalog, which `targets` already tracks.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [q, view, targets, inventoryTargets]);

    const rail = catalog ? [
        { id: INVENTORY, label: "In my inventory", color: "#16a34a", count: inventoryTargets.length },
        { id: ALL, label: "All targets", color: "#94a3b8", count: targets.length },
        ...catalog.categories.map((c, i) => ({
            id: c.id, label: c.label, color: CATEGORY_COLORS[c.id] || "#6b7280",
            count: targets.filter((t) => t.category === c.id).length, divider: i === 0,
        })),
    ] : [];

    const listTitle = q
        ? `${shown.length} result${shown.length === 1 ? "" : "s"} for "${query.trim()}"`
        : view === INVENTORY ? "Found in your inventory · most assets first"
        : view === ALL ? "All supported targets" : categoryLabel(view);

    // ── assets ──
    const loadingAssets = Boolean(deviceType) && assetsFor !== deviceType;
    const aq = assetQuery.trim().toLowerCase();
    const visibleAssets = aq
        ? assets.filter((a) => `${a.asset_name} ${a.ip_address || ""}`.toLowerCase().includes(aq))
        : assets;
    const versionText = version ? `${version.group ? `${version.group} ` : ""}${version.label}` : "";
    const rank = { match: 0, unknown: 1, different: 2 };
    const matched = [];
    const other = [];
    visibleAssets.forEach((a) => {
        if (!selected || a.inferred_device_type !== selected.family) {
            other.push({ asset: a, state: "other", text: "Type not detected" });
            return;
        }
        if (!selected.versions.length) {
            matched.push({ asset: a, state: "match", text: `Detected ${selected.label}` });
        } else if (a.inferred_device_variant === deviceType) {
            matched.push({ asset: a, state: "match", text: `Matches ${versionText}` });
        } else if (!a.inferred_device_variant) {
            matched.push({ asset: a, state: "unknown", text: "Version not detected" });
        } else {
            const v = selected.versions.find((x) => x.device_type === a.inferred_device_variant);
            matched.push({
                asset: a, state: "different",
                text: v ? `${v.group ? `${v.group} ` : ""}${v.label} detected` : "Different version",
            });
        }
    });
    matched.sort((x, y) => rank[x.state] - rank[y.state]);
    const chosenAsset = assets.find((a) => String(a.id) === String(assetId)) || null;

    const pickTarget = (t) => {
        if (selected && t.id === selected.id) return;
        onChange({ device_type: preferredDeviceType(t), asset_id: "" }, null);
        setAssetQuery("");
        setShowOther(false);
    };
    // Same target, other version: the asset list is the same family, so the
    // asset stays - unless it is known to run a different version.
    const pickVersion = (v) => {
        const keep = chosenAsset && (!chosenAsset.inferred_device_variant
            || chosenAsset.inferred_device_variant === v.device_type);
        onChange({ device_type: v.device_type, ...(keep ? {} : { asset_id: "" }) }, keep ? chosenAsset : null);
    };
    // Picking an asset whose version is known selects that version too, so a
    // "detected" row is one click, not two.
    const pickAsset = (a) => {
        const variant = a.inferred_device_variant;
        const switchTo = selected && variant && variant !== deviceType
            && selected.versions.some((v) => v.device_type === variant) ? variant : null;
        onChange({ asset_id: String(a.id), ...(switchTo ? { device_type: switchTo } : {}) }, a);
    };

    if (loadError) return <div className="tp-error" role="alert">{loadError}</div>;
    if (!catalog) return <div className="tp-loading">Loading supported targets…</div>;

    const versionGroups = selected
        ? [...new Set(selected.versions.map((v) => v.group || ""))].map((g) => ({
            group: g, versions: selected.versions.filter((v) => (v.group || "") === g),
        }))
        : [];

    const assetRow = ({ asset: a, state, text }) => {
        const on = String(a.id) === String(assetId);
        return (
            <button type="button" key={a.id} role="radio" aria-checked={on}
                    className={`tp-asset ${on ? "on" : ""}`} onClick={() => pickAsset(a)}>
                <AssetIcon icon={a.resolved_icon} size={34} />
                <span className="tp-asset-text">
                    <span className="tp-asset-name">{a.asset_name}</span>
                    <span className="tp-asset-meta">
                        {a.ip_address || "No IP"}
                        {(a.os_name || a.os_version) && ` · ${[a.os_name, a.os_version].filter(Boolean).join(" ")}`}
                    </span>
                </span>
                <span className={`tp-match ${state}`}>{text}</span>
                <span className="tp-radio" aria-hidden="true"><span /></span>
            </button>
        );
    };

    return (
        <div className="target-picker">
            <section className="tp-section">
                <div className="tp-head">
                    <h3><span className="tp-num">1</span>What do you want to {mode === "audit" ? "audit" : "harden"}?</h3>
                    <span className="tp-muted">{targets.length} supported targets</span>
                </div>
                <label className="tp-search">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                        <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
                    </svg>
                    <input
                        type="search"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search - e.g. Linux, FortiGate, SQL"
                        aria-label="Search supported targets"
                    />
                </label>

                <div className="tp-body">
                    <div className="tp-rail" role="tablist" aria-label="Categories">
                        {rail.map((r) => (
                            <div key={r.id}>
                                {r.divider && <div className="tp-rail-divider" />}
                                <button type="button" role="tab" aria-selected={!q && view === r.id}
                                        className={`tp-rail-item ${!q && view === r.id ? "on" : ""}`}
                                        onClick={() => { setCategory(r.id); setQuery(""); }}>
                                    <span className="tp-swatch" style={{ background: r.color }} />
                                    <span className="tp-rail-label">{r.label}</span>
                                    <span className="tp-rail-count">{r.count}</span>
                                </button>
                            </div>
                        ))}
                    </div>

                    <div className="tp-list">
                        <div className="tp-list-title">{listTitle}</div>
                        {shown.length === 0 ? (
                            <div className="tp-empty">
                                {q ? `Nothing matches "${query.trim()}".` : "No assets of a supported type in your inventory yet."}
                                {" "}
                                <button type="button" className="tp-link" onClick={() => { setQuery(""); setCategory(ALL); }}>
                                    Show all targets
                                </button>
                            </div>
                        ) : (
                            <div className="tp-grid" role="radiogroup" aria-label="Target">
                                {shown.map((t) => {
                                    const on = selected?.id === t.id;
                                    return (
                                        <button type="button" key={t.id} role="radio" aria-checked={on}
                                                className={`tp-card ${on ? "on" : ""}`} onClick={() => pickTarget(t)}>
                                            <AssetIcon icon={t.icon} size={40} color={CATEGORY_COLORS[t.category]}
                                                       monogram={t.monogram} title={t.label} />
                                            <span className="tp-card-text">
                                                <span className="tp-card-name">{t.label}</span>
                                                <span className="tp-card-sub">{t.description}</span>
                                                <span className={`tp-card-count ${t.asset_count ? "has" : ""}`}>
                                                    {t.asset_count ? `${t.asset_count} in inventory` : "No assets yet"}
                                                </span>
                                            </span>
                                        </button>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>

                {selected && (
                    <div className="tp-versions">
                        <span className="tp-versions-label">Version</span>
                        {selected.versions.length === 0 ? (
                            <span className="tp-muted tp-versions-none">No version to choose.</span>
                        ) : (
                            <div className="tp-version-groups" role="radiogroup" aria-label="Version">
                                {versionGroups.map((g) => (
                                    <div key={g.group || "v"} className="tp-version-group">
                                        {g.group && <span className="tp-version-group-label">{g.group}</span>}
                                        {g.versions.map((v) => (
                                            <button type="button" key={v.device_type} role="radio"
                                                    aria-checked={v.device_type === deviceType}
                                                    className={`tp-chip ${v.device_type === deviceType ? "on" : ""}`}
                                                    onClick={() => pickVersion(v)}>
                                                {v.label}
                                                {v.asset_count > 0 && <span className="tp-chip-count">{v.asset_count}</span>}
                                            </button>
                                        ))}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
                {errors.device_type && <span className="error-message">{errors.device_type}</span>}
            </section>

            <section className="tp-section tp-assets">
                <div className="tp-head">
                    <h3><span className="tp-num">2</span>Which asset?</h3>
                    {assets.length > 6 && (
                        <label className="tp-search small">
                            <input type="search" value={assetQuery} onChange={(e) => setAssetQuery(e.target.value)}
                                   placeholder="Search name or IP" aria-label="Search assets" />
                        </label>
                    )}
                </div>
                {loadingAssets ? (
                    <div className="tp-loading">Loading assets…</div>
                ) : matched.length === 0 && other.length === 0 ? (
                    <div className="tp-empty">
                        No {selected ? selected.label : ""} asset in your inventory yet - add it under Asset Management first.
                    </div>
                ) : (
                    <div className="tp-asset-list" role="radiogroup" aria-label="Asset">
                        {matched.map(assetRow)}
                        {other.length > 0 && (
                            <>
                                <button type="button" className="tp-other-toggle" aria-expanded={showOther}
                                        onClick={() => setShowOther((s) => !s)}>
                                    {showOther ? "▾" : "▸"} Other / unknown type ({other.length})
                                </button>
                                {showOther && other.map(assetRow)}
                            </>
                        )}
                    </div>
                )}
                {errors.asset_id && <span className="error-message">{errors.asset_id}</span>}
            </section>

            {selected && (
                <div className="tp-summary" aria-live="polite">
                    <AssetIcon icon={selected.icon} size={36} color={CATEGORY_COLORS[selected.category]} monogram={selected.monogram} />
                    <div className="tp-summary-text">
                        <span>You are {VERB[mode]} <b>{selected.label}{version ? ` ${versionText}` : ""}</b>
                            {chosenAsset ? <> on <b>{chosenAsset.asset_name}</b> ({chosenAsset.ip_address || "no IP"})</> : " - choose an asset"}
                        </span>
                        <span className="tp-muted">Connects via {selected.connects_via}</span>
                    </div>
                </div>
            )}
        </div>
    );
}

export default TargetPicker;
