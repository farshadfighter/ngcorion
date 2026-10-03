import { useCallback, useEffect, useMemo, useState } from "react";
import api from "../../config/api.js";
import { isRtl, t, n } from "../../i18n";
import { formatDate, formatDateTime, relativeDays } from "../../utils/dates.js";
import { tb } from "../../i18n/backendText";
import { CollectForm } from "./CollectForm.jsx";
import { MapModal } from "./MapModal.jsx";
import { CHANGE, COLLECTOR, KIND, SEVERITY, SOURCE, SOURCE_ORDER, errorText } from "./softwareFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Remediation.css";
import "../../assets/Software.css";

const ALL_PAGE = 150;

/** One asset's installed software: what is outside the distribution, what changed, and collecting it now. */
const collectedText = (col) => (col.summary?.first
    ? t("Collected {{count}} items. Changes are shown from the next collection on.", { count: col.items })
    : t("Collected {{count}} items: {{added}} added, {{updated}} updated, {{removed}} removed.",
        { count: col.items, added: col.added, updated: col.updated, removed: col.removed }));

export function AssetSoftwareDrawer({ assetId, canWrite, canMap, onClose, onChanged, justCollected = null }) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [reload, setReload] = useState(0);
    const [collecting, setCollecting] = useState(false);
    const [notice, setNotice] = useState(justCollected ? collectedText(justCollected) : null);
    const [showAll, setShowAll] = useState(false);
    const [mapping, setMapping] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get(`/api/software/assets/${assetId}`)
            .then(({ data: d }) => { if (alive) { setData(d); setError(null); } })
            .catch((e) => alive && setError(errorText(e, t("Could not load the software list"))));
        return () => { alive = false; };
    }, [assetId, reload]);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && !mapping && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose, mapping]);

    const refresh = useCallback(() => { setReload((x) => x + 1); onChanged?.(); }, [onChanged]);

    const collected = (col) => {
        setCollecting(false);
        setNotice(collectedText(col));
        refresh();
    };

    const a = data?.asset;
    const s = data?.summary;
    const items = data?.items || [];
    const empty = data && !items.length;

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="sw-asset-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer sw-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="sw-asset-title">{a ? a.name : t("Software")}</h2>
                        {a && (
                            <span className="bkm-sub">
                                {a.ip_address && <span className="bkm-mono">{a.ip_address}</span>}
                                {[a.os_name, a.os_version].filter(Boolean).length > 0 && <> · <span className="sw-ltr-inline">{[a.os_name, a.os_version].filter(Boolean).join(" ")}</span></>}
                            </span>
                        )}
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label={t("Close")} onClick={onClose}>×</button>
                </header>

                <div className="bkm-drawer-body sw-drawer-body">
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                    {!data && !error && <div className="bkm-muted">{t("Loading…")}</div>}
                    {notice && <div className="bkm-note bkm-note-ok" role="status">{notice}</div>}

                    {empty && (
                        <section className="sw-panel">
                            <h3 className="bkm-h3">{t("No software list yet")}</h3>
                            <p className="alr-hint">
                                {t("The list is collected by every Linux and Windows audit of this asset. Apache, MongoDB, SQL Server, Cisco and Fortinet audits record the version of the product itself.")}
                            </p>
                            {data.collections[0]?.status === "failed" && (
                                <div className="bkm-note bkm-note-orange">
                                    {t("The last collection failed: {{error}}", { error: tb(data.collections[0].error || "") })}
                                </div>
                            )}
                            {canWrite && !collecting && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setCollecting(true)}>{t("Collect now…")}</button>}
                        </section>
                    )}

                    {collecting && a && (
                        <section className="sw-panel">
                            <h3 className="bkm-h3">{t("Collect now")}</h3>
                            <CollectForm asset={{ ...a, id: a.id }} onDone={collected} onCancel={() => setCollecting(false)} />
                        </section>
                    )}

                    {data && !empty && (
                        <>
                            <Summary data={data} canWrite={canWrite && !collecting} onCollect={() => { setNotice(null); setCollecting(true); }} />
                            <div className="sw-two">
                                <section className="sw-panel">
                                    {!showAll ? (
                                        <OutsideDistro items={items} canMap={canMap} onMap={setMapping}
                                                       onShowAll={() => setShowAll(true)} total={s.packages + s.hotfixes} />
                                    ) : (
                                        <AllItems items={items} onBack={() => setShowAll(false)} />
                                    )}
                                </section>
                                <Changes assetId={assetId} data={data} reload={reload} />
                            </div>
                        </>
                    )}
                </div>
            </aside>
            {mapping && (
                <MapModal product={mapping} onClose={() => setMapping(null)}
                          onSaved={() => { setMapping(null); refresh(); }} />
            )}
        </div>
    );
}

function Summary({ data, canWrite, onCollect }) {
    const s = data.summary;
    const last = s.last;
    const total = SOURCE_ORDER.reduce((sum, k) => sum + (s.by_source[k] || 0), 0) || 1;
    return (
        <section className="sw-panel sw-summary">
            <div className="bkm-row-between">
                <div>
                    <h3 className="sw-big">
                        {s.packages ? t("{{count}} installed packages", { count: s.packages }) : t("Versions read by audits")}
                        {s.hotfixes > 0 && <span className="sw-big-sub"> · {t("{{count}} Windows updates", { count: s.hotfixes })}</span>}
                    </h3>
                    {last && (
                        <span className="bkm-sub">
                            {last.trigger === "manual"
                                ? t("Collected on demand on {{date}}", { date: formatDateTime(last.collected_at) })
                                : t("From the {{source}} of {{date}}", { source: COLLECTOR[last.collector] || last.collector, date: formatDateTime(last.collected_at) })}
                            {last.audit_session_id && ` · ${t("session #{{id}}", { id: last.audit_session_id })}`}
                            {s.previous_at && ` · ${t("previous collection {{when}}", { when: relativeDays(s.previous_at) })}`}
                        </span>
                    )}
                </div>
                {canWrite && <button type="button" className="bkm-btn bkm-btn-sm" onClick={onCollect}>{t("Collect now…")}</button>}
            </div>
            {s.packages > 0 && (
                <>
                    <div className="sw-bar" aria-hidden="true">
                        {SOURCE_ORDER.filter((k) => s.by_source[k]).map((k) => (
                            <i key={k} className={SOURCE[k].cls} style={{ width: `${(100 * s.by_source[k]) / total}%` }} />
                        ))}
                    </div>
                    <div className="sw-legend">
                        {SOURCE_ORDER.filter((k) => s.by_source[k]).map((k) => (
                            <span key={k} className={`sw-src ${SOURCE[k].cls}`}>{SOURCE[k].label} <b>{n(s.by_source[k])}</b></span>
                        ))}
                    </div>
                </>
            )}
            <div className="sw-mini-stats">
                <span><b className={s.vulnerable ? "bkm-red" : ""}>{n(s.vulnerable)}</b> {t("with known vulnerabilities")}</span>
                <span><b className={s.unidentified ? "bkm-orange" : ""}>{n(s.unidentified)}</b> {t("unidentified")}</span>
                <span><b>{n(s.outside_distro)}</b> {t("outside the distribution repository")}</span>
            </div>
        </section>
    );
}

export function CveCell({ item }) {
    if (item.cve) {
        const sev = SEVERITY[item.cve.severity];
        return (
            <span>
                <span className={`sw-sev ${sev?.cls || ""}`}>{t("{{count}} CVEs", { count: item.cve.count })} · {sev?.label || item.cve.severity}</span>
                {item.cve.kev && <span className="sw-kev">KEV</span>}
                {item.cve.fixed_in?.length > 0 && <span className="bkm-sub">{t("fixed in")} <span className="sw-ltr-inline">{item.cve.fixed_in.join(", ")}</span></span>}
            </span>
        );
    }
    if (item.status === "unknown") return <span className="bkm-pill bkm-pill-amber">{t("Unidentified")}</span>;
    if (item.status === "internal") return <span className="bkm-pill bkm-pill-muted">{t("Internal software")}</span>;
    if (item.source === "distro") return <span className="bkm-muted bkm-small">{t("Distribution advisories · next phase")}</span>;
    if (item.status === "known" && item.nvd) return <span className="bkm-muted">{t("None known")}</span>;
    return <span className="bkm-muted">—</span>;
}

function OutsideDistro({ items, canMap, onMap, onShowAll, total }) {
    // Sub-packages of one product (php8.4-cli, php8.4-curl...) under one line.
    const groups = useMemo(() => {
        const out = new Map();
        for (const i of items.filter((x) => x.source !== "distro" && x.kind !== "hotfix" && x.status !== "component")) {
            const key = i.status === "known" ? `k:${i.label}:${i.version}` : `i:${i.id}`;
            const g = out.get(key);
            if (g) g.names.push(i.name);
            else out.set(key, { ...i, names: [i.name] });
        }
        return [...out.values()].sort((x, y) => (y.cve?.count || 0) - (x.cve?.count || 0)
            || (x.status === "unknown") - (y.status === "unknown") || x.label.localeCompare(y.label));
    }, [items]);
    return (
        <>
            <div className="bkm-row-between">
                <h3 className="bkm-h3">{t("Outside the distribution repository")}</h3>
                <button type="button" className="bkm-link" onClick={onShowAll}>{t("All packages ({{count}})", { count: total })}</button>
            </div>
            {groups.length === 0 ? (
                <p className="alr-hint">{t("Everything on this asset comes from its distribution's own repository.")}</p>
            ) : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table sw-table sw-fixed">
                        <thead><tr><th style={{ width: "32%" }}>{t("Software")}</th><th style={{ width: "24%" }}>{t("Version")}</th><th style={{ width: "20%" }}>{t("Source")}</th><th style={{ width: "24%" }}>{t("Vulnerabilities")}</th></tr></thead>
                        <tbody>
                            {groups.map((g) => (
                                <tr key={g.id}>
                                    <td>
                                        <b className="sw-name">{g.status === "known" ? g.label : g.name}</b>
                                        <span className="bkm-sub sw-ltr-inline sw-clip" title={g.names.join(", ")}>
                                            {g.status === "known" ? (g.names.length > 2 ? t("{{name}} and {{count}} more", { name: g.names[0], count: g.names.length - 1 }) : g.names.join(" · ")) : (g.publisher || KIND[g.kind])}
                                        </span>
                                    </td>
                                    <td><span className="sw-ver" title={g.version}>{g.version || "?"}</span></td>
                                    <td><span className={`sw-src ${SOURCE[g.source]?.cls || ""}`}>{g.origin || SOURCE[g.source]?.label || g.source}</span></td>
                                    <td>
                                        <CveCell item={g} />
                                        {g.status === "unknown" && canMap && (
                                            <button type="button" className="bkm-btn bkm-btn-sm sw-ml" onClick={() => onMap({
                                                key: g.match_key, label: g.name, asset_count: 1, versions: [{ version: g.version }],
                                                sources: [g.source], origins: g.origin ? [g.origin] : [],
                                            })}>{t("Identify…")}</button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </>
    );
}

function AllItems({ items, onBack }) {
    const [q, setQ] = useState("");
    const [source, setSource] = useState("");
    const [limit, setLimit] = useState(ALL_PAGE);
    const rows = useMemo(() => {
        const s = q.trim().toLowerCase();
        return items.filter((i) => (!source || i.source === source)
            && (!s || `${i.name} ${i.version || ""} ${i.origin || ""} ${i.label}`.toLowerCase().includes(s)));
    }, [items, q, source]);
    const sources = SOURCE_ORDER.filter((k) => items.some((i) => i.source === k));
    return (
        <>
            <div className="bkm-row-between">
                <h3 className="bkm-h3">{t("All packages")}</h3>
                <button type="button" className="bkm-link" onClick={onBack}>{t("Back to outside the distribution")}</button>
            </div>
            <div className="sw-filter-row">
                <label className="bkm-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={q} onChange={(e) => { setQ(e.target.value); setLimit(ALL_PAGE); }} placeholder={t("Search package")} aria-label={t("Search package")} />
                </label>
                <select className="bkm-select" value={source} onChange={(e) => { setSource(e.target.value); setLimit(ALL_PAGE); }} aria-label={t("Source")}>
                    <option value="">{t("Every source")}</option>
                    {sources.map((k) => <option key={k} value={k}>{SOURCE[k].label}</option>)}
                </select>
            </div>
            <div className="bkm-table-wrap sw-scroll">
                <table className="bkm-table sw-table sw-fixed">
                    <thead><tr><th style={{ width: "32%" }}>{t("Name")}</th><th style={{ width: "24%" }}>{t("Version")}</th><th style={{ width: "20%" }}>{t("Source")}</th><th style={{ width: "24%" }}>{t("Vulnerabilities")}</th></tr></thead>
                    <tbody>
                        {rows.slice(0, limit).map((i) => (
                            <tr key={i.id}>
                                <td><span className="sw-ltr-inline sw-name">{i.name}</span>{i.kind !== "package" && <span className="bkm-sub">{KIND[i.kind]}</span>}</td>
                                <td><span className="sw-ver" title={i.version}>{i.version || "?"}</span>{i.arch && <span className="bkm-sub sw-ltr-inline">{i.arch}</span>}</td>
                                <td><span className={`sw-src ${SOURCE[i.source]?.cls || ""}`}>{i.origin || SOURCE[i.source]?.label}</span></td>
                                <td><CveCell item={i} /></td>
                            </tr>
                        ))}
                        {rows.length === 0 && <tr><td colSpan={4} className="bkm-muted">{t("Nothing matches")}</td></tr>}
                    </tbody>
                </table>
            </div>
            <div className="bkm-row-between sw-foot">
                <span className="bkm-muted bkm-small">{t("{{shown}} of {{total}}", { shown: n(Math.min(limit, rows.length)), total: n(rows.length) })}</span>
                {rows.length > limit && <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setLimit(limit + ALL_PAGE)}>{t("Show more")}</button>}
            </div>
        </>
    );
}

function Changes({ assetId, data, reload }) {
    const okCollections = data.collections.filter((c) => c.status === "ok");
    const [selected, setSelected] = useState(null);
    const current = data.collections.find((c) => c.id === selected) || data.summary.last || okCollections[0];
    const [changes, setChanges] = useState(null);
    const [expanded, setExpanded] = useState(false);

    useEffect(() => {
        if (!current) return undefined;
        let alive = true;
        api.get(`/api/software/assets/${assetId}/changes`, { params: { collection_id: current.id } })
            .then(({ data: d }) => alive && setChanges(d))
            .catch(() => alive && setChanges([]));
        return () => { alive = false; };
    }, [assetId, current?.id, reload]); // eslint-disable-line react-hooks/exhaustive-deps

    const list = changes || [];
    // Changes outside the distribution first: they are the ones to look at.
    const notable = list.filter((c) => c.source !== "distro" || c.change !== "updated");
    const routine = list.filter((c) => c.source === "distro" && c.change === "updated");
    const shown = expanded ? [...notable, ...routine] : notable.slice(0, 14);
    const hidden = expanded ? 0 : routine.length + Math.max(0, notable.length - 14);

    return (
        <section className="sw-panel">
            <h3 className="bkm-h3">{t("Changes since the previous collection")}</h3>
            {current && (
                <span className="bkm-sub">
                    {formatDate(current.collected_at)}
                    {current.summary?.first ? ` · ${t("first list")}` : ` · ${t("{{added}} added, {{updated}} updated, {{removed}} removed", { added: current.added, updated: current.updated, removed: current.removed })}`}
                </span>
            )}
            <div className="sw-changes">
                {current?.summary?.first && <p className="alr-hint">{t("This is the first list of this asset; changes start with the next collection.")}</p>}
                {shown.map((c) => (
                    <div key={c.id} className="sw-change">
                        <span className={`sw-tag ${CHANGE[c.change].cls}`}>{CHANGE[c.change].label}</span>
                        <span className="sw-change-main">
                            <span className="sw-ltr-inline sw-name">{c.name}</span>{" "}
                            {c.change === "updated"
                                ? <span className="sw-vers-change"><span className="sw-ver" title={c.old_version}>{c.old_version}</span><span aria-hidden="true">{isRtl() ? "←" : "→"}</span><span className="sw-ver" title={c.new_version}>{c.new_version}</span></span>
                                : <span className="sw-ver" title={c.change === "removed" ? c.old_version : c.new_version}>{c.change === "removed" ? c.old_version : c.new_version}</span>}
                        </span>
                        <span className={`sw-src ${SOURCE[c.source]?.cls || ""} bkm-small`}>{c.origin || SOURCE[c.source]?.short}</span>
                    </div>
                ))}
                {hidden > 0 && (
                    <button type="button" className="bkm-link sw-more" onClick={() => setExpanded(true)}>
                        {routine.length > 0 && !expanded
                            ? t("Show {{count}} more, mostly updates from the distribution repository", { count: hidden })
                            : t("Show {{count}} more", { count: hidden })}
                    </button>
                )}
                {changes && !list.length && !current?.summary?.first && <p className="alr-hint">{t("Nothing changed.")}</p>}
            </div>

            <h4 className="sw-h4">{t("History")}</h4>
            <ul className="sw-history">
                {data.collections.slice(0, 12).map((c) => (
                    <li key={c.id}>
                        <button type="button" className={`sw-hist ${current?.id === c.id ? "is-on" : ""}`} disabled={c.status !== "ok"}
                                onClick={() => setSelected(c.id)}>
                            <span className={`sw-dot ${c.status === "ok" ? "is-ok" : "is-bad"}`} aria-hidden="true" />
                            <span>
                                {formatDateTime(c.collected_at)} · {c.trigger === "manual" ? t("collected on demand") : (COLLECTOR[c.collector] || c.collector)}
                                <span className="bkm-sub">
                                    {c.status !== "ok" ? tb(c.error || "") : c.summary?.first ? t("first list · {{count}} items", { count: c.items })
                                        : t("{{count}} changes", { count: c.added + c.updated + c.removed })}
                                </span>
                            </span>
                        </button>
                    </li>
                ))}
            </ul>
            <p className="alr-hint">{t("Changes are kept for a year.")}</p>
        </section>
    );
}

