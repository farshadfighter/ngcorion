/**
 * Asset groups (/assets/groups): named sets of assets for group audits and scheduled audits.
 *
 * A dynamic group is a set of conditions that all have to hold (type, zone, owner, tag, IP range,
 * ...), evaluated each time the group is used, so a new asset that matches is in it at once; a static
 * group lists its assets by hand. Endpoints: /api/asset-groups (app/modules/asset_groups/router.py).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { n, t } from "../../i18n";
import { useAssetFormOptions } from "../AssetList/useAssetFormOptions";
import { FIELDS, OPS, STATUSES, errorText, ruleText } from "./groupFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/AssetGroups.css";

const emptyRule = () => ({ field: "type", op: "eq", value: "" });
const emptyGroup = () => ({ name: "", description: "", kind: "dynamic", rules: [emptyRule()], asset_ids: [] });

/** Names for the ids rules refer to: asset types, zones, owners, locations. */
function useRuleOptions() {
    const { assetTypes, owners, locations } = useAssetFormOptions();
    const [zones, setZones] = useState([]);
    const [tags, setTags] = useState([]);
    useEffect(() => {
        api.get("/api/risk/zones").then(({ data }) => setZones(data || [])).catch(() => setZones([]));
        api.get("/api/asset-groups/tags").then(({ data }) => setTags(data || [])).catch(() => setTags([]));
    }, []);
    return useMemo(() => ({
        type: (assetTypes || []).map((x) => ({ value: x.id, label: x.type_name })),
        owner: (owners || []).map((x) => ({ value: x.id, label: x.full_name || x.owner_name || `#${x.id}` })),
        location: (locations || []).map((x) => ({ value: x.id, label: x.site_name || x.location_name || `#${x.id}` })),
        zone: zones.map((z) => ({ value: z.id, label: z.name })),
        status: Object.entries(STATUSES).map(([value, label]) => ({ value, label })),
        tags: tags.map((x) => x.tag),
    }), [assetTypes, owners, locations, zones, tags]);
}

export function AssetGroupsPage() {
    const canWrite = usePermission("asset_list", "write");
    const canAudit = usePermission("auditing", "write");
    const options = useRuleOptions();
    const [groups, setGroups] = useState(null);
    const [error, setError] = useState(null);
    const [editing, setEditing] = useState(null);   // a group object, or emptyGroup() for a new one
    const [deleting, setDeleting] = useState(null);
    const [search, setSearch] = useState("");

    const load = useCallback(() => {
        api.get("/api/asset-groups")
            .then(({ data }) => setGroups(data))
            .catch((e) => setError(errorText(e, t("Could not load the asset groups"))));
    }, []);
    useEffect(load, [load]);

    const open = (g) => {
        if (!g.id) return setEditing(emptyGroup());
        api.get(`/api/asset-groups/${g.id}`)
            .then(({ data }) => setEditing({ ...data, asset_ids: data.assets.map((a) => a.id), rules: data.rules.length ? data.rules : [emptyRule()] }))
            .catch((e) => setError(errorText(e, t("Could not load the group"))));
    };

    const remove = (g) => {
        api.delete(`/api/asset-groups/${g.id}`)
            .then(() => { setDeleting(null); load(); })
            .catch((e) => { setDeleting(null); setError(errorText(e, t("Could not delete the group"))); });
    };

    const shown = (groups || []).filter((g) => !search.trim() || g.name.toLowerCase().includes(search.trim().toLowerCase()));

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <span className="bkm-crumb">{t("Assets")} › {t("Asset groups")}</span>
                    <h1>{t("Asset groups")}</h1>
                    <p>{t("Group assets by type, zone, owner, tag or IP range to audit them together and schedule their audits. A dynamic group is re-evaluated every time it is used, so new assets that match join it on their own.")}</p>
                </div>
                <div className="bkm-actions">
                    {canAudit && <Link className="bkm-btn" to="/audit/group-runs">{t("Group audits")}</Link>}
                    {canWrite && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => open({})}>{t("New group")}</button>}
                </div>
            </div>

            <div className="bkm-toolbar">
                <label className="bkm-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("Search groups…")} aria-label={t("Search groups")} />
                </label>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead>
                            <tr>
                                <th>{t("Group")}</th>
                                <th>{t("Kind")}</th>
                                <th>{t("Membership")}</th>
                                <th>{t("Assets")}</th>
                                <th>{t("Schedules")}</th>
                                <th />
                            </tr>
                        </thead>
                        <tbody>
                            {shown.map((g) => (
                                <tr key={g.id}>
                                    <td>
                                        <button type="button" className="bkm-link ag-name" onClick={() => open(g)} dir="auto">{g.name}</button>
                                        {g.description && <div className="bkm-sub" dir="auto">{g.description}</div>}
                                    </td>
                                    <td><span className={`bkm-pill ${g.kind === "dynamic" ? "bkm-pill-run" : "bkm-pill-muted"}`}>
                                        {g.kind === "dynamic" ? t("Dynamic") : t("Static")}</span></td>
                                    <td className="ag-rules-cell">
                                        {g.kind === "dynamic"
                                            ? (g.rules.length ? g.rules.map((r, i) => <span key={i} className="ag-rule-chip">{ruleText(r, options)}</span>)
                                                : <span className="bkm-muted">{t("Every asset")}</span>)
                                            : <span className="bkm-muted">{t("Chosen by hand")}</span>}
                                    </td>
                                    <td><b>{n(g.asset_count)}</b></td>
                                    <td>{g.schedules ? n(g.schedules) : <span className="bkm-muted">—</span>}</td>
                                    <td className="bkm-right bkm-nowrap">
                                        {canAudit && g.asset_count > 0 && (
                                            <Link className="bkm-btn bkm-btn-sm" to={`/audit/group-runs?group=${g.id}`}>{t("Audit…")}</Link>
                                        )}
                                        {canWrite && (
                                            <button type="button" className="bkm-btn bkm-btn-sm ag-ml" onClick={() => setDeleting(g)}>{t("Delete")}</button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                            {groups && shown.length === 0 && (
                                <tr><td colSpan={6}>
                                    <div className="bkm-empty">
                                        <b>{groups.length ? t("No group matches") : t("No asset groups yet")}</b>
                                        <span>{t("For example: every Linux server in the DMZ, or every asset tagged pci.")}</span>
                                    </div>
                                </td></tr>
                            )}
                            {!groups && !error && <tr><td colSpan={6} className="bkm-muted">{t("Loading…")}</td></tr>}
                        </tbody>
                    </table>
                </div>
            </section>

            {editing && <GroupDrawer group={editing} options={options} canWrite={canWrite}
                                     onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load(); }} />}
            {deleting && (
                <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="ag-del-title">
                    <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={() => setDeleting(null)} />
                    <div className="alr-modal">
                        <h2 id="ag-del-title">{t("Delete group")}</h2>
                        <p>{t("Delete the group \"{{name}}\"? Its assets are not changed.", { name: deleting.name })}</p>
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={() => setDeleting(null)}>{t("Cancel")}</button>
                            <button type="button" className="bkm-btn ag-danger" onClick={() => remove(deleting)}>{t("Delete")}</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

/** One condition: field, operator, value. */
function RuleRow({ rule, options, onChange, onRemove, disabled }) {
    const f = FIELDS[rule.field] || FIELDS.type;
    const set = (patch) => onChange({ ...rule, ...patch });
    const choices = options[f.input];
    return (
        <div className="ag-rule">
            <select className="bkm-select" value={rule.field} disabled={disabled} aria-label={t("Field")}
                    onChange={(e) => set({ field: e.target.value, op: FIELDS[e.target.value].ops[0], value: "" })}>
                {Object.entries(FIELDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <select className="bkm-select" value={rule.op} disabled={disabled} aria-label={t("Condition")}
                    onChange={(e) => set({ op: e.target.value })}>
                {f.ops.map((op) => <option key={op} value={op}>{OPS[op]}</option>)}
            </select>
            {Array.isArray(choices) ? (
                <select className="bkm-select" value={rule.value} disabled={disabled} aria-label={t("Value")}
                        onChange={(e) => set({ value: e.target.value })}>
                    <option value="">{t("Choose…")}</option>
                    {choices.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                </select>
            ) : (
                <>
                    <input className="bkm-select" value={rule.value} disabled={disabled} aria-label={t("Value")}
                           dir={f.input === "cidr" ? "ltr" : "auto"} list={f.input === "tag" ? "ag-tag-list" : undefined}
                           placeholder={f.input === "cidr" ? "10.0.0.0/24" : f.input === "tag" ? "pci" : ""}
                           onChange={(e) => set({ value: e.target.value })} />
                </>
            )}
            {!disabled && <button type="button" className="bkm-icon-btn" onClick={onRemove} aria-label={t("Remove condition")} title={t("Remove condition")}>✕</button>}
        </div>
    );
}

function GroupDrawer({ group, options, canWrite, onClose, onSaved }) {
    const [g, setG] = useState(group);
    const [preview, setPreview] = useState(null);
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    const [allAssets, setAllAssets] = useState(null);
    const [pick, setPick] = useState("");
    const set = (patch) => setG((cur) => ({ ...cur, ...patch }));
    const complete = g.rules.filter((r) => r.value !== "" && r.value !== null);

    // live preview of a dynamic group's members
    const rulesKey = JSON.stringify(complete);
    useEffect(() => {
        if (g.kind !== "dynamic") return undefined;
        const timer = setTimeout(() => {
            api.post("/api/asset-groups/preview", { rules: JSON.parse(rulesKey) })
                .then(({ data }) => { setPreview(data); setError(null); })
                .catch((e) => { setPreview(null); setError(errorText(e, t("These conditions cannot be evaluated"))); });
        }, 300);
        return () => clearTimeout(timer);
    }, [rulesKey, g.kind]);

    useEffect(() => {
        if (g.kind === "static" && allAssets === null) {
            api.get("/api/assets/").then(({ data }) => setAllAssets(data || [])).catch(() => setAllAssets([]));
        }
    }, [g.kind, allAssets]);

    const members = useMemo(() => {
        const byId = new Map((allAssets || []).map((a) => [a.id, a]));
        const known = new Map((group.assets || []).map((a) => [a.id, a]));
        return g.asset_ids.map((id) => byId.get(id) || known.get(id) || { id, asset_name: `#${id}` });
    }, [g.asset_ids, allAssets, group.assets]);

    const candidates = useMemo(() => {
        const q = pick.trim().toLowerCase();
        if (!q || !allAssets) return [];
        const have = new Set(g.asset_ids);
        return allAssets.filter((a) => !have.has(a.id) && [a.asset_name, a.ip_address, a.hostname].some((v) => (v || "").toLowerCase().includes(q))).slice(0, 8);
    }, [pick, allAssets, g.asset_ids]);

    const save = () => {
        setSaving(true);
        setError(null);
        const body = { name: g.name, description: g.description || null, kind: g.kind,
                       rules: g.kind === "dynamic" ? complete : [], asset_ids: g.kind === "static" ? g.asset_ids : [] };
        const req = g.id ? api.put(`/api/asset-groups/${g.id}`, body) : api.post("/api/asset-groups", body);
        req.then(onSaved).catch((e) => setError(errorText(e, t("Could not save the group")))).finally(() => setSaving(false));
    };

    const shownAssets = g.kind === "dynamic" ? (preview?.assets || []) : members;
    const count = g.kind === "dynamic" ? preview?.count : g.asset_ids.length;

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="ag-drawer-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ag-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="ag-drawer-title" dir="auto">{g.id ? g.name : t("New group")}</h2>
                        <span className="bkm-sub">{count === undefined ? "" : t("{{value}} assets in the group now", { value: n(count ?? 0) })}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <label className="alr-lbl">{t("Name")}
                        <input className="bkm-select" value={g.name} maxLength={120} disabled={!canWrite} dir="auto"
                               onChange={(e) => set({ name: e.target.value })} placeholder={t("e.g. Linux servers in the DMZ")} />
                    </label>
                    <label className="alr-lbl">{t("Description")}
                        <input className="bkm-select" value={g.description || ""} maxLength={2000} disabled={!canWrite} dir="auto"
                               onChange={(e) => set({ description: e.target.value })} />
                    </label>
                    <div className="ag-seg" role="radiogroup" aria-label={t("Kind")}>
                        {[["dynamic", t("Dynamic: by conditions")], ["static", t("Static: chosen by hand")]].map(([k, label]) => (
                            <button key={k} type="button" role="radio" aria-checked={g.kind === k} disabled={!canWrite}
                                    className={g.kind === k ? "is-on" : ""} onClick={() => set({ kind: k })}>{label}</button>
                        ))}
                    </div>

                    {g.kind === "dynamic" ? (
                        <section className="ag-box">
                            <h3 className="bkm-h3">{t("Conditions (all must hold)")}</h3>
                            {g.rules.map((r, i) => (
                                <RuleRow key={i} rule={r} options={options} disabled={!canWrite}
                                         onChange={(nr) => set({ rules: g.rules.map((x, j) => (j === i ? nr : x)) })}
                                         onRemove={() => set({ rules: g.rules.filter((_, j) => j !== i) })} />
                            ))}
                            <datalist id="ag-tag-list">{options.tags.map((tag) => <option key={tag} value={tag} />)}</datalist>
                            {canWrite && g.rules.length < 20 && (
                                <button type="button" className="bkm-btn bkm-btn-sm ag-add" onClick={() => set({ rules: [...g.rules, emptyRule()] })}>
                                    {t("+ Add condition")}
                                </button>
                            )}
                            {complete.length === 0 && <p className="alr-hint">{t("With no condition the group holds every asset.")}</p>}
                        </section>
                    ) : canWrite && (
                        <section className="ag-box">
                            <h3 className="bkm-h3">{t("Add assets")}</h3>
                            <input className="bkm-select" value={pick} onChange={(e) => setPick(e.target.value)}
                                   placeholder={t("Search by name or IP address…")} aria-label={t("Search assets")} />
                            {candidates.map((a) => (
                                <button key={a.id} type="button" className="ag-cand"
                                        onClick={() => { set({ asset_ids: [...g.asset_ids, a.id] }); setPick(""); }}>
                                    <span dir="auto">{a.asset_name}</span><span className="bkm-mono bkm-small" dir="ltr">{a.ip_address}</span>
                                </button>
                            ))}
                        </section>
                    )}

                    <section>
                        <h3 className="bkm-h3">
                            {g.kind === "dynamic" ? t("Assets that match now") : t("Assets in the group")}
                            {count !== undefined && count !== null && <span className="bkm-muted"> · {n(count)}</span>}
                        </h3>
                        <div className="ag-members">
                            {shownAssets.map((a) => (
                                <div key={a.id} className="ag-member">
                                    <span dir="auto" className="bkm-strong">{a.asset_name}</span>
                                    <span className="bkm-mono bkm-small" dir="ltr">{a.ip_address || "—"}</span>
                                    {a.type_name && <span className="bkm-small bkm-muted">{a.type_name}</span>}
                                    {(a.tags || []).map((tag) => <span key={tag} className="ag-tag">{tag}</span>)}
                                    {g.kind === "static" && canWrite && (
                                        <button type="button" className="bkm-icon-btn ag-push" aria-label={t("Remove from group")} title={t("Remove from group")}
                                                onClick={() => set({ asset_ids: g.asset_ids.filter((x) => x !== a.id) })}>✕</button>
                                    )}
                                </div>
                            ))}
                            {shownAssets.length === 0 && <p className="bkm-muted">{t("No assets yet")}</p>}
                            {g.kind === "dynamic" && preview && preview.count > preview.assets.length && (
                                <p className="bkm-muted bkm-small">{t("and {{value}} more", { value: n(preview.count - preview.assets.length) })}</p>
                            )}
                        </div>
                    </section>
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{canWrite ? t("Cancel") : t("Close")}</button>
                    {canWrite && (
                        <button type="button" className="bkm-btn bkm-btn-primary" disabled={saving || !g.name.trim()} onClick={save}>
                            {saving ? t("Saving…") : t("Save group")}
                        </button>
                    )}
                </footer>
            </aside>
        </div>
    );
}

export default AssetGroupsPage;
