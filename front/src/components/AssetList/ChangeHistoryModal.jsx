import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssetChangeHistory } from "../../store/assetSlice";
import "../../assets/ChangeHistory.css";
import { t, uiLocale } from "../../i18n";

// Matches the four Asset List tabs (see AssetList.jsx) so filtering here
// maps onto the same grouping a user already knows from editing an asset.
const CATEGORIES = [
    { id: "all", label: t("All") },
    { id: "overview", label: t("Overview") },
    { id: "network", label: t("Network & System") },
    { id: "location", label: t("Location & Owner") },
    { id: "security", label: t("Security & Audit") },
];

const CATEGORY_DOT = { overview: "#16a34a", network: "#2563eb", location: "#7c3aed", security: "#d97706" };

function initials(name) {
    if (!name) return "?";
    const parts = name.trim().split(/\s+/);
    return ((parts[0]?.[0] || "") + (parts[1]?.[0] || "")).toUpperCase() || name[0].toUpperCase();
}

function dateGroupLabel(dateObj) {
    const now = new Date();
    const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diffDays = Math.round((startOfDay(now) - startOfDay(dateObj)) / 86400000);
    if (diffDays === 0) return t("Today");
    if (diffDays === 1) return t("Yesterday");
    return dateObj.toLocaleDateString(uiLocale(),  { year: "numeric", month: "long", day: "numeric" });
}

// Flattens the raw AssetLog entries (one "update" log can bundle several
// field changes) into one timeline row per field change.
function flattenEntries(logs) {
    const rows = [];
    for (const log of logs) {
        const changes = log.details?.changes || [];
        for (const change of changes) {
            rows.push({
                key: `${log.id}-${change.field}`,
                ...change,
                timestamp: log.timestamp,
                username: log.username || t("Unknown"),
            });
        }
    }
    return rows;
}

export const ChangeHistoryModal = ({ asset, isOpen, onClose }) => {
    const dispatch = useDispatch();
    const { changeHistory, isLoadingChangeHistory } = useSelector((state) => state.assets);
    const [activeCategory, setActiveCategory] = useState("all");

    // Fetched once on mount - the modal unmounts on close (see AssetList.jsx's
    // `{showHistoryModal && selectedAsset && (...)}` guard) and remounts fresh
    // for the next asset, so activeCategory's useState("all") already starts
    // correct without resetting it here.
    useEffect(() => {
        if (isOpen && asset) {
            dispatch(fetchAssetChangeHistory(asset.id));
        }
    }, [isOpen, asset, dispatch]);

    const entries = useMemo(() => flattenEntries(changeHistory), [changeHistory]);

    const counts = useMemo(() => {
        const c = { all: entries.length, overview: 0, network: 0, location: 0, security: 0 };
        for (const e of entries) c[e.category] = (c[e.category] || 0) + 1;
        return c;
    }, [entries]);

    const visible = activeCategory === "all" ? entries : entries.filter((e) => e.category === activeCategory);

    const groups = useMemo(() => {
        const byLabel = new Map();
        for (const entry of visible) {
            const label = dateGroupLabel(new Date(entry.timestamp));
            if (!byLabel.has(label)) byLabel.set(label, []);
            byLabel.get(label).push(entry);
        }
        return [...byLabel.entries()];
    }, [visible]);

    if (!isOpen || !asset) return null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content2 modal-large ach-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header ach-header">
                    <div>
                        <div className="ach-title-row">
                            <h3>{t("Change History")}</h3>
                            <span className="ach-asset-badge">{asset.asset_name}</span>
                        </div>
                        <div className="ach-subtitle">
                            {[asset.asset_type_name, asset.hostname, asset.asset_role].filter(Boolean).join(" · ") || "—"}
                        </div>
                    </div>
                    <button className="modal-close" onClick={onClose}>✕</button>
                </div>

                <div className="ach-chips">
                    {CATEGORIES.map((c) => (
                        <button
                            key={c.id}
                            className={`ach-chip ${activeCategory === c.id ? "active" : ""}`}
                            onClick={() => setActiveCategory(c.id)}
                        >
                            {c.label} ({counts[c.id] ?? 0})
                        </button>
                    ))}
                </div>

                <div className="modal-body ach-timeline">
                    {isLoadingChangeHistory ? (
                        <div className="ach-empty">{t("Loading…")}</div>
                    ) : visible.length === 0 ? (
                        <div className="ach-empty">{t("No changes recorded yet.")}</div>
                    ) : (
                        groups.map(([label, rows]) => (
                            <div key={label}>
                                <div className="ach-date-label">{label}</div>
                                {rows.map((entry, i) => (
                                    <div className="ach-entry" key={entry.key}>
                                        {i < rows.length - 1 && <div className="ach-entry-line" />}
                                        <div className="ach-entry-dot" style={{ background: CATEGORY_DOT[entry.category] || "#9ca3af" }} />
                                        <div className="ach-entry-body">
                                            <div className="ach-entry-head">
                                                <span className="ach-entry-category" style={{ color: CATEGORY_DOT[entry.category], background: `${CATEGORY_DOT[entry.category]}18` }}>
                                                    {CATEGORIES.find((c) => c.id === entry.category)?.label || entry.category}
                                                </span>
                                                <span className="ach-entry-field">{entry.label}</span>
                                            </div>
                                            <div className="ach-entry-diff">
                                                <span className="ach-pill ach-pill-old">{entry.old ?? "—"}</span>
                                                <span className="ach-arrow">→</span>
                                                <span className="ach-pill ach-pill-new">{entry.new ?? "—"}</span>
                                            </div>
                                            <div className="ach-entry-meta">
                                                <span className="ach-avatar">{initials(entry.username)}</span>
                                                {entry.username} · {new Date(entry.timestamp).toLocaleTimeString(uiLocale(),  { hour: "2-digit", minute: "2-digit" })}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ))
                    )}
                </div>

                <div className="ach-footer">
                    {t("Every field change across Overview, Network & System, Location & Owner and Security & Audit is captured automatically when this asset is edited. No manual entry required.")}
                </div>
            </div>
        </div>
    );
};

export default ChangeHistoryModal;
