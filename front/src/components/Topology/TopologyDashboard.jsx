/**
 * Topology page: the canvas, link editing and the topology checks (isolated nodes, single points
 * of failure); and the Neighbours view (?tab=neighbors): what the devices report over LLDP / CDP,
 * which draws most links by itself. ?link=ID opens a link (the "Network link lost" alert).
 */
import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useSearchParams } from "react-router-dom";
import {
    fetchTopology,
    createTopologyLink,
    updateTopologyLink,
    deleteTopologyLink,
    saveNodePosition,
    validateTopology,
    clearMessages,
} from "../../store/topologySlice.jsx";
import { TopologyCanvas } from "./TopologyCanvas.jsx";
import { TopologyNeighbors } from "./TopologyNeighbors.jsx";
import "../../assets/Topology.css";
import { n, t as tr } from "../../i18n";
import { tv } from "../../i18n/backendText";
import { formatDateTime } from "../../utils/dates.js";

const LINK_TYPES = ["ethernet", "fiber", "wireless", "logical"];
const LINK_STATUSES = ["active", "planned", "down"];

const SEVERITY_CLASS = { low: "topo-badge-low", medium: "topo-badge-medium", high: "topo-badge-high" };
const ORIGIN = { lldp: "LLDP", cdp: "CDP" };

export const TopologyDashboard = () => {
    const dispatch = useDispatch();
    const { nodes, links, isLoading, isMutating, error, successMessage, validation } = useSelector(
        (state) => state.topology
    );

    const [selectedLink, setSelectedLink] = useState(null);
    const [showValidation, setShowValidation] = useState(false);
    const [search, setSearch] = useSearchParams();
    const tab = search.get("tab") === "neighbors" ? "neighbors" : "map";
    const focusLink = Number(search.get("link")) || null;

    useEffect(() => {
        if (tab === "map") dispatch(fetchTopology());
    }, [dispatch, tab]);

    // Open the link the URL names (an alert, "Show on map" in Neighbours) once the graph is loaded.
    const [focused, setFocused] = useState(null);
    if (focusLink && focused !== focusLink && links.length) {
        const hit = links.find((l) => l.id === focusLink);
        if (hit) {
            setFocused(focusLink);
            setSelectedLink(hit);
        }
    }

    const go = (name, linkId) => {
        const p = new URLSearchParams();
        if (name === "neighbors") p.set("tab", "neighbors");
        if (linkId) p.set("link", String(linkId));
        setFocused(null);
        setSearch(p, { replace: !linkId });
    };
    const found = links.filter((l) => l.origin === "lldp" || l.origin === "cdp");
    const missing = found.filter((l) => l.missing_since).length;

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleConnect = (payload) => {
        dispatch(createTopologyLink(payload));
    };

    const handleEdgeClick = (link) => {
        setSelectedLink(link);
    };

    const handleNodeDragStop = (assetId, posX, posY) => {
        dispatch(saveNodePosition({ assetId, posX, posY }));
    };

    const handleUpdateSelected = (field, value) => {
        setSelectedLink((prev) => ({ ...prev, [field]: value }));
    };

    const handleSaveSelected = () => {
        if (!selectedLink || selectedLink.link_type === "hosted") return;
        const { id, source_interface, destination_interface, link_type, speed_mbps, vlan, subnet, status } =
            selectedLink;
        dispatch(
            updateTopologyLink({
                linkId: id,
                changes: { source_interface, destination_interface, link_type, speed_mbps, vlan, subnet, status },
            })
        );
    };

    const handleDeleteSelected = () => {
        if (!selectedLink || selectedLink.link_type === "hosted") return;
        dispatch(deleteTopologyLink(selectedLink.id));
        setSelectedLink(null);
    };

    const handleValidate = () => {
        setShowValidation(true);
        dispatch(validateTopology());
    };

    const nodeById = (id) => nodes.find((node) => node.id === Number(id));
    const tabs = (
        <div className="topology-tabs" role="tablist" aria-label={tr("Topology")}>
            <button type="button" role="tab" aria-selected={tab === "map"} className={`topology-tab ${tab === "map" ? "is-on" : ""}`}
                    onClick={() => go("map")}>{tr("Map")}</button>
            <button type="button" role="tab" aria-selected={tab === "neighbors"} className={`topology-tab ${tab === "neighbors" ? "is-on" : ""}`}
                    onClick={() => go("neighbors")}>{tr("Neighbours (LLDP/CDP)")}</button>
        </div>
    );

    if (tab === "neighbors") {
        return (
            <div className="topology-container">
                <div className="topology-toolbar">{tabs}</div>
                <TopologyNeighbors onShowLink={(id) => go("map", id)} />
            </div>
        );
    }

    return (
        <div className="topology-container">
            <div className="topology-toolbar">
                {tabs}
                <div className="topology-toolbar-info">
                    <span>{tr("{{length}} assets", { length: n(nodes.length) })}</span>
                    <span className="topology-toolbar-sep">•</span>
                    <span>{tr("{{length}} links", { length: n(links.length) })}</span>
                    {found.length > 0 && <><span className="topology-toolbar-sep">•</span>
                        <span>{tr("{{value}} found by LLDP/CDP", { value: n(found.length) })}</span></>}
                    {missing > 0 && <><span className="topology-toolbar-sep">•</span>
                        <span className="topology-missing-count">{tr("{{value}} no longer reported", { value: n(missing) })}</span></>}
                </div>
                <div className="topology-toolbar-actions">
                    <button className="topology-btn" onClick={() => dispatch(fetchTopology())} disabled={isLoading}>
                        <i className="fa-solid fa-arrows-rotate" /> {" "}{tr("Refresh")}
                    </button>
                    <button className="topology-btn topology-btn-primary" onClick={handleValidate}>
                        <i className="fa-solid fa-clipboard-check" /> {" "}{tr("Validate")}
                    </button>
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`topology-toast ${error ? "topology-toast-error" : "topology-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="topology-body">
                <div className="topology-canvas-wrap">
                    {isLoading ? (
                        <div className="topology-empty">{tr("Loading topology…")}</div>
                    ) : nodes.length === 0 ? (
                        <div className="topology-empty">
                            {tr("No assets yet. Add assets in Asset Management to see them here.")}
                        </div>
                    ) : (
                        <TopologyCanvas
                            nodes={nodes}
                            links={links}
                            onConnect={handleConnect}
                            onEdgeClick={handleEdgeClick}
                            onNodeDragStop={handleNodeDragStop}
                        />
                    )}
                    <div className="topology-hint">
                        {tr("Drag a device to rearrange it - the layout is saved. Drag from a device's port to another device's port to create a link. Click a link to edit it.")}
                        <div className="topology-legend">
                            <span><i />{tr("Link")}</span>
                            <span><i className="is-planned" />{tr("Planned, or a hosted VM")}</span>
                            <span><i className="is-missing" />{tr("Found by LLDP/CDP, no longer reported")}</span>
                        </div>
                    </div>
                </div>

                {selectedLink && (
                    <aside className="topology-panel">
                        <div className="topology-panel-header">
                            <h3>{selectedLink.link_type === "hosted" ? tr("Hosted-on relationship") : tr("Link details")}</h3>
                            <button className="topology-panel-close" onClick={() => setSelectedLink(null)}>
                                <i className="fa-solid fa-xmark" />
                            </button>
                        </div>
                        <div className="topology-panel-body">
                            <div className="topology-field">
                                <label>{selectedLink.link_type === "hosted" ? tr("Server") : tr("From")}</label>
                                <div className="topology-field-static">
                                    {nodeById(String(selectedLink.source_asset_id))?.name || selectedLink.source_asset_id}
                                    {selectedLink.source_interface ? ` (${selectedLink.source_interface})` : ""}
                                </div>
                            </div>
                            <div className="topology-field">
                                <label>{selectedLink.link_type === "hosted" ? tr("Hosted asset") : tr("Destination")}</label>
                                <div className="topology-field-static">
                                    {nodeById(String(selectedLink.destination_asset_id))?.name ||
                                        selectedLink.destination_asset_id}
                                    {selectedLink.destination_interface
                                        ? ` (${selectedLink.destination_interface})`
                                        : ""}
                                </div>
                            </div>
                            {selectedLink.link_type !== "hosted" && (
                                <div className="topology-field">
                                    <label>{tr("Origin")}</label>
                                    <p className="topology-field-note">
                                        {ORIGIN[selectedLink.origin]
                                            ? tr("Found in the devices' {{protocol}} tables.", { protocol: ORIGIN[selectedLink.origin] })
                                            : tr("Drawn by hand.")}
                                        {selectedLink.last_seen_at && <> {tr("Last reported {{when}}.", { when: formatDateTime(selectedLink.last_seen_at) })}</>}
                                    </p>
                                    {selectedLink.missing_since && (
                                        <p className="topology-field-note is-warn">
                                            {tr("The devices stopped reporting this link on {{when}}: the cable may be unplugged or moved. It is removed after 30 days.",
                                                { when: formatDateTime(selectedLink.missing_since) })}
                                        </p>
                                    )}
                                </div>
                            )}
                            {selectedLink.link_type === "hosted" ? (
                                <>
                                    {selectedLink.vlan && (
                                        <div className="topology-field">
                                            <label>{tr("VLAN")}</label>
                                            <div className="topology-field-static">{selectedLink.vlan}</div>
                                        </div>
                                    )}
                                    <p className="topology-panel-hint">
                                        {tr("Set from Asset Management → the hosted asset's \"Hosted on server\" field, not editable here.")}
                                    </p>
                                </>
                            ) : (
                                <>
                                    <div className="topology-field">
                                        <label>{tr("Link type")}</label>
                                        <select
                                            value={selectedLink.link_type || "ethernet"}
                                            onChange={(e) => handleUpdateSelected("link_type", e.target.value)}
                                        >
                                            {LINK_TYPES.map((t) => (
                                                <option key={t} value={t}>
                                                    {t}
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="topology-field">
                                        <label>{tr("Status")}</label>
                                        <select
                                            value={selectedLink.status || "active"}
                                            onChange={(e) => handleUpdateSelected("status", e.target.value)}
                                        >
                                            {LINK_STATUSES.map((s) => (
                                                <option key={s} value={s}>
                                                    {s}
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="topology-field">
                                        <label>{tr("Speed (Mbps)")}</label>
                                        <input
                                            type="number"
                                            value={selectedLink.speed_mbps ?? ""}
                                            onChange={(e) =>
                                                handleUpdateSelected(
                                                    "speed_mbps",
                                                    e.target.value ? Number(e.target.value) : null
                                                )
                                            }
                                        />
                                    </div>
                                    <div className="topology-field">
                                        <label>{tr("VLAN")}</label>
                                        <input
                                            type="text"
                                            value={selectedLink.vlan || ""}
                                            onChange={(e) => handleUpdateSelected("vlan", e.target.value || null)}
                                        />
                                    </div>
                                    <div className="topology-field">
                                        <label>{tr("Subnet")}</label>
                                        <input
                                            type="text"
                                            value={selectedLink.subnet || ""}
                                            onChange={(e) => handleUpdateSelected("subnet", e.target.value || null)}
                                        />
                                    </div>
                                </>
                            )}
                        </div>
                        {selectedLink.link_type !== "hosted" && (
                            <div className="topology-panel-footer">
                                <button className="topology-btn topology-btn-danger" onClick={handleDeleteSelected}
                                        title={ORIGIN[selectedLink.origin] ? tr("Not drawn again at the next read; Neighbours → Add to map brings it back.") : undefined}>
                                    {ORIGIN[selectedLink.origin] ? tr("Remove from map") : tr("Delete")}
                                </button>
                                <button
                                    className="topology-btn topology-btn-primary"
                                    onClick={handleSaveSelected}
                                    disabled={isMutating}
                                >
                                    {tr("Save")}
                                </button>
                            </div>
                        )}
                    </aside>
                )}

                {showValidation && (
                    <aside className="topology-panel">
                        <div className="topology-panel-header">
                            <h3>{tr("Validation")}</h3>
                            <button className="topology-panel-close" onClick={() => setShowValidation(false)}>
                                <i className="fa-solid fa-xmark" />
                            </button>
                        </div>
                        <div className="topology-panel-body">
                            {validation.isLoading ? (
                                <div className="topology-empty">{tr("Checking…")}</div>
                            ) : validation.findings.length === 0 ? (
                                <div className="topology-empty">{tr("No structural issues found.")}</div>
                            ) : (
                                <ul className="topology-findings">
                                    {validation.findings.map((f, i) => (
                                        <li key={i} className="topology-finding">
                                            <span className={`topo-badge ${SEVERITY_CLASS[f.severity] || ""}`}>
                                                {tv(f.severity)}
                                            </span>
                                            <span>{f.message}</span>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </aside>
                )}
            </div>
        </div>
    );
};

export default TopologyDashboard;
