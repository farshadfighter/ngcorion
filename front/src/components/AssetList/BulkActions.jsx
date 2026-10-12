/**
 * Bulk edit of the selected assets (POST /api/assets/bulk): add or remove tags, set the owner,
 * location, status or risk zone, add to a static group, or delete. Every changed asset gets its own
 * change-history entry; deleting asks for the number of assets to be typed.
 */
import { useEffect, useState } from "react";

import api from "../../config/api";
import { usePermission } from "../../hooks/usePermission";
import { n, t } from "../../i18n";
import { STATUSES, errorText } from "../AssetGroups/groupFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/AssetGroups.css";

const ACTIONS = {
    add_tags: t("Add tag"),
    remove_tags: t("Remove tag"),
    set_owner: t("Set owner"),
    set_location: t("Set location"),
    set_status: t("Set status"),
    set_zone: t("Set zone"),
    add_to_group: t("Add to group"),
    delete: t("Delete"),
};

export function BulkBar({ selectedIds, onClear, onDone, owners, locations }) {
    const canWrite = usePermission("asset_list", "write");
    const canDelete = usePermission("asset_list", "delete");
    const canZone = usePermission("risk", "write");
    const [action, setAction] = useState(null);
    if (!selectedIds.size) return null;
    const shown = Object.keys(ACTIONS).filter((a) => (a === "delete" ? canDelete : a === "set_zone" ? canZone && canWrite : canWrite));
    return (
        <>
            <div className="ag-bulk" role="toolbar" aria-label={t("Bulk actions")}>
                <b>{t("{{value}} selected", { value: n(selectedIds.size) })}</b>
                {shown.map((a) => (
                    <button key={a} type="button" className={a === "delete" ? "ag-bulk-danger" : ""} onClick={() => setAction(a)}>{ACTIONS[a]}</button>
                ))}
                <button type="button" className="ag-bulk-clear" onClick={onClear}>{t("Clear selection")}</button>
            </div>
            {action && <BulkModal action={action} ids={[...selectedIds]} owners={owners} locations={locations}
                                  onClose={() => setAction(null)} onDone={(msg) => { setAction(null); onDone(msg, action); }} />}
        </>
    );
}

function BulkModal({ action, ids, owners, locations, onClose, onDone }) {
    const [value, setValue] = useState("");
    const [tags, setTags] = useState([]);
    const [zones, setZones] = useState([]);
    const [groups, setGroups] = useState([]);
    const [confirm, setConfirm] = useState("");
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        if (action === "add_tags" || action === "remove_tags") api.get("/api/asset-groups/tags").then(({ data }) => setTags(data)).catch(() => {});
        if (action === "set_zone") api.get("/api/risk/zones").then(({ data }) => setZones(data)).catch(() => {});
        if (action === "add_to_group") api.get("/api/asset-groups").then(({ data }) => setGroups(data.filter((g) => g.kind === "static"))).catch(() => {});
    }, [action]);

    const choices = {
        set_owner: owners.map((o) => ({ value: o.id, label: o.full_name || `#${o.id}` })),
        set_location: locations.map((l) => ({ value: l.id, label: l.site_name || l.location_name || `#${l.id}` })),
        set_status: Object.entries(STATUSES).filter(([k]) => k !== "inactive").map(([value, label]) => ({ value, label })),
        set_zone: zones.map((z) => ({ value: z.id, label: z.name })),
        add_to_group: groups.map((g) => ({ value: g.id, label: g.name })),
    }[action];
    const isTags = action === "add_tags" || action === "remove_tags";
    const tagList = value.split(",").map((x) => x.trim()).filter(Boolean);
    const ready = action === "delete" ? Number(confirm) === ids.length : isTags ? tagList.length > 0 : value !== "";

    const apply = () => {
        setBusy(true);
        setError(null);
        const body = { asset_ids: ids, action };
        if (isTags) body.tags = tagList;
        else if (action === "delete") body.confirm_count = Number(confirm);
        else body.value = value;
        api.post("/api/assets/bulk", body)
            .then(({ data }) => {
                if (action === "delete") {
                    const refused = data.refused?.length || 0;
                    onDone(refused
                        ? t("{{deleted}} assets deleted; {{refused}} could not be deleted.", { deleted: n(data.deleted), refused: n(refused) })
                        : t("{{deleted}} assets deleted.", { deleted: n(data.deleted) }));
                } else {
                    onDone(t("{{value}} assets changed.", { value: n(data.changed) }));
                }
            })
            .catch((e) => setError(errorText(e, t("The change could not be made"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="ag-bulk-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal">
                <h2 id="ag-bulk-title">{ACTIONS[action]} · {t("{{value}} assets", { value: n(ids.length) })}</h2>
                {isTags && (
                    <>
                        <label className="alr-lbl">{t("Tags, separated by commas")}
                            <input className="bkm-select" value={value} list="ag-bulk-tags" dir="ltr" autoFocus
                                   onChange={(e) => setValue(e.target.value)} placeholder="pci, web, prod" />
                        </label>
                        <datalist id="ag-bulk-tags">{tags.map((x) => <option key={x.tag} value={x.tag} />)}</datalist>
                        {tags.length > 0 && (
                            <div className="ag-tags">
                                {tags.slice(0, 20).map((x) => (
                                    <button key={x.tag} type="button" className="ag-tag" onClick={() => setValue(tagList.includes(x.tag) ? value : [...tagList, x.tag].join(", "))}>
                                        {x.tag} · {n(x.count)}
                                    </button>
                                ))}
                            </div>
                        )}
                    </>
                )}
                {choices && (
                    <label className="alr-lbl">{ACTIONS[action]}
                        <select className="bkm-select" value={value} onChange={(e) => setValue(e.target.value)}>
                            <option value="">{t("Choose…")}</option>
                            {choices.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                        </select>
                    </label>
                )}
                {action === "add_to_group" && groups.length === 0 && <p className="alr-hint">{t("There is no static group yet. Make one under Assets › Asset groups.")}</p>}
                {action === "set_zone" && <p className="alr-hint">{t("The risk score of each asset is recalculated with the new zone.")}</p>}
                {action === "delete" && (
                    <>
                        <p className="bkm-note bkm-note-error">{t("Deleting removes the assets with their audit results, backups and history. This cannot be undone.")}</p>
                        <label className="alr-lbl">{t("Type {{value}} to confirm", { value: n(ids.length) })}
                            <input className="bkm-select ag-confirm-input" value={confirm} inputMode="numeric" autoFocus
                                   onChange={(e) => setConfirm(e.target.value.replace(/[۰-۹]/g, (d) => "۰۱۲۳۴۵۶۷۸۹".indexOf(d)))} />
                        </label>
                    </>
                )}
                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className={`bkm-btn ${action === "delete" ? "ag-danger" : "bkm-btn-primary"}`} disabled={busy || !ready} onClick={apply}>
                        {busy ? t("Working…") : action === "delete" ? t("Delete {{value}} assets", { value: n(ids.length) }) : t("Apply")}
                    </button>
                </div>
            </div>
        </div>
    );
}

export default BulkBar;
