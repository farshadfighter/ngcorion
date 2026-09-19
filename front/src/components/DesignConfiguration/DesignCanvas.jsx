import { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useParams } from "react-router-dom";
import { ReactFlow, Background, Controls, useNodesState, useEdgesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";
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
import { generateConfigurationJob } from "../../store/configurationSlice.jsx";
import { fetchAssets } from "../../store/assetSlice.jsx";
import "../../assets/DesignConfiguration.css";

const PALETTE = [
    { type: "router", label: "Router" },
    { type: "switch", label: "Switch" },
    { type: "firewall", label: "Firewall" },
    { type: "load_balancer", label: "Load Balancer" },
    { type: "wireless", label: "Wireless AP" },
    { type: "server", label: "Server" },
    { type: "storage", label: "Storage" },
    { type: "cloud", label: "Cloud" },
];

export const DesignCanvas = () => {
    const { versionId } = useParams();
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { currentVersion, error, successMessage } = useSelector((state) => state.design);
    const { assets } = useSelector((state) => state.assets);
    const { isGenerating } = useSelector((state) => state.configuration);

    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);
    const paletteDropCounter = useRef(0);
    const [selectedComponentId, setSelectedComponentId] = useState(null);
    const [selectedRelationshipId, setSelectedRelationshipId] = useState(null);
    const [jobName, setJobName] = useState("");
    const [showGenerate, setShowGenerate] = useState(false);

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
                data: {
                    label: c.label,
                    typeName: c.component_type,
                    subtitle: c.mapped_asset_name || undefined,
                    portCount: c.mapped_asset_port_count,
                },
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
                style: { stroke: "#1e3a5f", strokeWidth: 2 },
                data: { relationship: r },
            }))
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [currentVersion?.components.length, currentVersion?.relationships.length, versionId]);

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

    const handleGenerate = () => {
        dispatch(generateConfigurationJob({ designVersionId: Number(versionId), name: jobName || `v${currentVersion.version.version_number} config` }))
            .then((action) => {
                if (action.payload?.job?.id) {
                    navigate(`/design-configuration/jobs/${action.payload.job.id}`);
                }
            });
    };

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
                <button className="dc-btn dc-btn-primary" onClick={() => setShowGenerate(true)} disabled={isGenerating}>
                    <i className="fa-solid fa-gears" /> {isGenerating ? "Generating…" : "Generate Configuration"}
                </button>
            </div>

            {(error || successMessage) && (
                <div className={`dc-toast ${error ? "dc-toast-error" : "dc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dc-canvas-body">
                <aside className="dc-palette">
                    <h4>Add component</h4>
                    {PALETTE.map((p) => (
                        <button key={p.type} className="dc-palette-btn" onClick={() => handleAddComponent(p.type)}>
                            {p.label}
                        </button>
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
                                    value={selectedComponent.component_type}
                                    onChange={(e) =>
                                        dispatch(
                                            updateComponent({ componentId: selectedComponent.id, changes: { component_type: e.target.value } })
                                        )
                                    }
                                >
                                    {PALETTE.map((p) => (
                                        <option key={p.type} value={p.type}>{p.label}</option>
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

            {showGenerate && (
                <div className="dc-modal-backdrop" onClick={() => setShowGenerate(false)}>
                    <div className="dc-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>Generate configuration</h3>
                        <p className="dc-modal-hint">
                            Generates one configuration object per component mapped to a real asset. Components with
                            no asset mapped are skipped.
                        </p>
                        <div className="dc-field">
                            <label>Job name</label>
                            <input value={jobName} onChange={(e) => setJobName(e.target.value)} placeholder={`v${currentVersion.version.version_number} config`} />
                        </div>
                        <div className="dc-modal-actions">
                            <button className="dc-btn" onClick={() => setShowGenerate(false)}>Cancel</button>
                            <button
                                className="dc-btn dc-btn-primary"
                                onClick={() => {
                                    setShowGenerate(false);
                                    handleGenerate();
                                }}
                            >
                                Generate
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DesignCanvas;
