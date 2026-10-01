import { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams } from "react-router-dom";
import { ReactFlow, Background, Controls, Panel, useNodesState, useEdgesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";
import AssetIcon from "../shared/AssetIcon.jsx";
import IconLegend from "../shared/IconLegend.jsx";
import { ASSET_ICONS, ICON_GROUPS, iconKey } from "../shared/assetIcons.js";
import {
    fetchVersionDetail,
    createComponent,
    updateComponent,
    deleteComponent,
    mapComponentToAsset,
    createRelationship,
    updateRelationship,
    deleteRelationship,
    clearMessages,
} from "../../store/designSlice.jsx";
import { fetchAssets } from "../../store/assetSlice.jsx";
import "../../assets/DesignConfiguration.css";

// Every icon except the catch-all can be placed as a device type.
const PALETTE_GROUPS = ICON_GROUPS.filter((g) => g.family !== "other");

// A component mapped to a real asset is drawn exactly like that asset (its
// icon and vendor/OS badge); an unmapped one is a planned device - dashed,
// drawn from its component type.
const componentData = (c) => ({
    label: c.label,
    icon: c.mapped_asset_icon || c.component_type,
    typeName: c.component_type,
    subtitle: c.mapped_asset_name || undefined,
    badge: c.mapped_asset_badge || undefined,
    planned: !c.mapped_asset_id,
    portCount: c.mapped_asset_port_count,
});

export const DesignCanvas = () => {
    const { versionId } = useParams();
    const dispatch = useDispatch();
    const { currentVersion, error, successMessage } = useSelector((state) => state.design);
    const { assets } = useSelector((state) => state.assets);

    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);
    const paletteDropCounter = useRef(0);
    const [selectedComponentId, setSelectedComponentId] = useState(null);
    const [selectedRelationshipId, setSelectedRelationshipId] = useState(null);

    useEffect(() => {
        dispatch(fetchVersionDetail(versionId));
        dispatch(fetchAssets());
    }, [dispatch, versionId]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    // Rebuild the canvas from redux whenever the component/relationship lists
    // change shape (add/remove) - live drag position is handled locally by
    // useNodesState and only pushed back to redux on drag stop.
    useEffect(() => {
        if (!currentVersion) return;
        setNodes(
            currentVersion.components.map((c) => ({
                id: String(c.id),
                type: "device",
                position: { x: c.pos_x, y: c.pos_y },
                data: componentData(c),
            }))
        );
        setEdges(
            currentVersion.relationships.map((r) => ({
                id: String(r.id),
                source: String(r.source_component_id),
                target: String(r.destination_component_id),
                sourceHandle: r.source_interface || undefined,
                targetHandle: r.destination_interface || undefined,
                label: r.vlan ? `VLAN ${r.vlan}` : undefined,
                type: "smoothstep",
                pathOptions: { borderRadius: 8 },
                style: { stroke: "#1e3a5f", strokeWidth: 2 },
                data: { relationship: r },
            }))
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [currentVersion?.components.length, currentVersion?.relationships.length, versionId]);

    // The rebuild above only runs when components are added or removed, so a
    // type change, rename or asset mapping would otherwise leave the old icon
    // on the canvas. Patch node data in place - positions and selection stay.
    const dataSignature = useMemo(
        () => JSON.stringify((currentVersion?.components || []).map((c) => [
            c.id, c.label, c.component_type, c.mapped_asset_id, c.mapped_asset_icon, c.mapped_asset_badge,
        ])),
        [currentVersion]
    );
    useEffect(() => {
        if (!currentVersion) return;
        const byId = new Map(currentVersion.components.map((c) => [String(c.id), c]));
        setNodes((prev) => prev.map((n) => (byId.has(n.id) ? { ...n, data: componentData(byId.get(n.id)) } : n)));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [dataSignature]);

    const handleAddComponent = (type) => {
        paletteDropCounter.current += 1;
        const n = paletteDropCounter.current;
        dispatch(
            createComponent({
                versionId,
                payload: {
                    component_type: type,
                    label: `${type}-${n}`,
                    pos_x: 60 + ((n * 40) % 400),
                    pos_y: 60 + ((n * 60) % 300),
                },
            })
        );
    };

    const handleNodeDragStop = useCallback(
        (_event, node) => {
            dispatch(
                updateComponent({
                    componentId: Number(node.id),
                    changes: { pos_x: node.position.x, pos_y: node.position.y },
                })
            );
        },
        [dispatch]
    );

    const handleConnect = useCallback(
        (connection) => {
            dispatch(
                createRelationship({
                    versionId,
                    payload: {
                        source_component_id: Number(connection.source),
                        destination_component_id: Number(connection.target),
                        source_interface: connection.sourceHandle || null,
                        destination_interface: connection.targetHandle || null,
                    },
                })
            );
        },
        [dispatch, versionId]
    );

    const handleNodeClick = useCallback((_event, node) => {
        setSelectedRelationshipId(null);
        setSelectedComponentId(Number(node.id));
    }, []);

    const handleEdgeClick = useCallback((_event, edge) => {
        setSelectedComponentId(null);
        setSelectedRelationshipId(Number(edge.id));
    }, []);

    const selectedComponent = useMemo(
        () => currentVersion?.components.find((c) => c.id === selectedComponentId) || null,
        [currentVersion, selectedComponentId]
    );
    const selectedRelationship = useMemo(
        () => currentVersion?.relationships.find((r) => r.id === selectedRelationshipId) || null,
        [currentVersion, selectedRelationshipId]
    );

    if (!currentVersion) {
        return <div className="dc-container"><div className="dc-empty">Loading…</div></div>;
    }

    return (
        <div className="dc-canvas-page">
            <div className="dc-canvas-toolbar">
                <div className="dc-toolbar-info">
                    v{currentVersion.version.version_number} · {currentVersion.components.length} component(s) ·{" "}
                    {currentVersion.relationships.length} link(s)
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`dc-toast ${error ? "dc-toast-error" : "dc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dc-canvas-body">
                <aside className="dc-palette" aria-label="Add a device">
                    <h4>Add device</h4>
                    {PALETTE_GROUPS.map((g) => (
                        <div key={g.family} className="dc-palette-group">
                            <div className="dc-palette-family">
                                <span className="dc-palette-swatch" style={{ background: g.color }} />
                                {g.label}
                            </div>
                            <div className="dc-palette-grid">
                                {g.icons.map((k) => (
                                    <button key={k} className="dc-palette-btn" onClick={() => handleAddComponent(k)}
                                            title={`Add a ${ASSET_ICONS[k].label}`}>
                                        <AssetIcon icon={k} size={28} />
                                        <span>{ASSET_ICONS[k].label}</span>
                                    </button>
                                ))}
                            </div>
                        </div>
                    ))}
                </aside>

                <div className="dc-canvas-wrap">
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        nodeTypes={DEVICE_NODE_TYPES}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onNodeDragStop={handleNodeDragStop}
                        onConnect={handleConnect}
                        onNodeClick={handleNodeClick}
                        onEdgeClick={handleEdgeClick}
                        fitView
                        proOptions={{ hideAttribution: true }}
                    >
                        <Background gap={20} color="#e5e7eb" />
                        <Controls />
                        <Panel position="top-left">
                            <IconLegend showPlanned />
                        </Panel>
                    </ReactFlow>
                </div>

                {selectedComponent && (
                    <aside className="dc-panel">
                        <div className="dc-panel-header">
                            <h3>Component</h3>
                            <button className="dc-panel-close" onClick={() => setSelectedComponentId(null)}>
                                <i className="fa-solid fa-xmark" />
                            </button>
                        </div>
                        <div className="dc-panel-body">
                            <div className="dc-panel-device">
                                <AssetIcon
                                    icon={selectedComponent.mapped_asset_icon || selectedComponent.component_type}
                                    planned={!selectedComponent.mapped_asset_id}
                                    size={52}
                                />
                                <div>
                                    <div className="dc-panel-device-name">{selectedComponent.label}</div>
                                    <div className="dc-panel-device-type">
                                        {ASSET_ICONS[iconKey(selectedComponent.mapped_asset_icon || selectedComponent.component_type)].label}
                                        {selectedComponent.mapped_asset_badge ? ` · ${selectedComponent.mapped_asset_badge}` : ""}
                                    </div>
                                </div>
                            </div>
                            <p className="dc-panel-note">
                                {selectedComponent.mapped_asset_id
                                    ? "Drawn with the mapped asset's icon. Change it on the asset or its Asset Type."
                                    : "Planned device (dashed). Map it to an asset to draw it with that asset's icon."}
                            </p>
                            <div className="dc-field">
                                <label>Label</label>
                                <input
                                    value={selectedComponent.label}
                                    onChange={(e) =>
                                        dispatch(updateComponent({ componentId: selectedComponent.id, changes: { label: e.target.value } }))
                                    }
                                />
                            </div>
                            <div className="dc-field">
                                <label>Type</label>
                                <select
                                    value={iconKey(selectedComponent.component_type)}
                                    onChange={(e) =>
                                        dispatch(
                                            updateComponent({ componentId: selectedComponent.id, changes: { component_type: e.target.value } })
                                        )
                                    }
                                >
                                    {PALETTE_GROUPS.map((g) => (
                                        <optgroup key={g.family} label={g.label}>
                                            {g.icons.map((k) => (
                                                <option key={k} value={k}>{ASSET_ICONS[k].label}</option>
                                            ))}
                                        </optgroup>
                                    ))}
                                </select>
                            </div>
                            <div className="dc-field">
                                <label>Mapped asset</label>
                                <select
                                    value={selectedComponent.mapped_asset_id || ""}
                                    onChange={(e) =>
                                        e.target.value &&
                                        dispatch(
                                            mapComponentToAsset({ componentId: selectedComponent.id, assetId: Number(e.target.value) })
                                        )
                                    }
                                >
                                    <option value="">— Not mapped —</option>
                                    {assets.map((a) => (
                                        <option key={a.id} value={a.id}>{a.asset_name}</option>
                                    ))}
                                </select>
                            </div>
                        </div>
                        <div className="dc-panel-footer">
                            <button
                                className="dc-btn dc-btn-danger"
                                onClick={() => {
                                    dispatch(deleteComponent(selectedComponent.id));
                                    setSelectedComponentId(null);
                                }}
                            >
                                Delete
                            </button>
                        </div>
                    </aside>
                )}

                {selectedRelationship && (
                    <aside className="dc-panel">
                        <div className="dc-panel-header">
                            <h3>Link</h3>
                            <button className="dc-panel-close" onClick={() => setSelectedRelationshipId(null)}>
                                <i className="fa-solid fa-xmark" />
                            </button>
                        </div>
                        <div className="dc-panel-body">
                            <div className="dc-field">
                                <label>VLAN</label>
                                <input
                                    value={selectedRelationship.vlan || ""}
                                    onChange={(e) =>
                                        dispatch(
                                            updateRelationship({
                                                relationshipId: selectedRelationship.id,
                                                changes: { vlan: e.target.value || null },
                                            })
                                        )
                                    }
                                />
                            </div>
                            <div className="dc-field">
                                <label>Subnet</label>
                                <input
                                    value={selectedRelationship.subnet || ""}
                                    onChange={(e) =>
                                        dispatch(
                                            updateRelationship({
                                                relationshipId: selectedRelationship.id,
                                                changes: { subnet: e.target.value || null },
                                            })
                                        )
                                    }
                                />
                            </div>
                        </div>
                        <div className="dc-panel-footer">
                            <button
                                className="dc-btn dc-btn-danger"
                                onClick={() => {
                                    dispatch(deleteRelationship(selectedRelationship.id));
                                    setSelectedRelationshipId(null);
                                }}
                            >
                                Delete
                            </button>
                        </div>
                    </aside>
                )}
            </div>
        </div>
    );
};

export default DesignCanvas;
