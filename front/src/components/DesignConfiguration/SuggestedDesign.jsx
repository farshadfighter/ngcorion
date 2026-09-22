import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { ReactFlow, Background, Controls, Panel } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";
import { ZoneBandNode } from "./ZoneBandNode.jsx";
import { ZONES } from "../shared/designZones.js";
import {
    fetchDesignSuggestion,
    createDesign,
    fetchDesignDetail,
    fetchVersionDetail,
    mapComponentToAsset,
    clearMessages,
} from "../../store/designSlice.jsx";
import "../../assets/DesignConfiguration.css";

const NODE_TYPES = { ...DEVICE_NODE_TYPES, zoneBand: ZoneBandNode };

// Generous padding around each zone's device nodes: DeviceNode's own
// width/height varies with its port count, so this errs wide enough that
// the dashed zone outline never clips a label or a port row.
const ZONE_PAD_X = 90;
const ZONE_PAD_TOP = 56;
const ZONE_PAD_BOTTOM = 110;

// Read-only preview of a standard SAFE campus design sized to the real asset
// inventory, with real assets slotted into matching roles wherever possible
// (see app/modules/design/suggestion.py). "Create this design" turns it into
// a real, editable Design by reusing the existing template-creation and
// asset-mapping endpoints - nothing here writes to the database until that
// button is clicked.
export const SuggestedDesign = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { suggestion, isLoading, error } = useSelector((state) => state.design);
    const [name, setName] = useState("");
    const [isCreating, setIsCreating] = useState(false);

    useEffect(() => {
        dispatch(fetchDesignSuggestion());
    }, [dispatch]);

    useEffect(() => {
        if (!error) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, dispatch]);

    const { nodes, edges } = useMemo(() => {
        if (!suggestion) return { nodes: [], edges: [] };

        const deviceNodes = suggestion.components.map((c) => ({
            id: c.key,
            type: "device",
            position: { x: c.pos_x, y: c.pos_y },
            data: {
                label: c.label,
                typeName: c.component_type,
                subtitle: c.suggested_asset_name || "no matching asset in inventory",
                portCount: c.suggested_asset_port_count,
                // This canvas has nodesConnectable={false} - individual port
                // handles can't be dragged from anyway, and a real device's
                // full port count (e.g. 48) would balloon the box far past
                // the template's fixed column spacing. The true count still
                // shows as text (see DeviceNode's displayPortCount).
                showPortHandles: false,
                dashed: !c.suggested_asset_id,
                color: c.suggested_asset_id ? "#1e3a5f" : "#9ca3af",
            },
            draggable: false,
            zIndex: 1,
        }));

        // One dashed background band per zone present, sized to the
        // bounding box of the components it contains - drawn at a lower
        // zIndex so device nodes always sit on top of it, not behind it.
        const byZone = new Map();
        suggestion.components.forEach((c) => {
            if (!byZone.has(c.zone)) byZone.set(c.zone, []);
            byZone.get(c.zone).push(c);
        });
        const zoneNodes = Array.from(byZone.entries()).map(([zoneId, comps]) => {
            const zone = ZONES[zoneId] || { label: zoneId, color: "#f3f4f6", border: "#e5e7eb" };
            const minX = Math.min(...comps.map((c) => c.pos_x));
            const maxX = Math.max(...comps.map((c) => c.pos_x));
            const minY = Math.min(...comps.map((c) => c.pos_y));
            const maxY = Math.max(...comps.map((c) => c.pos_y));
            return {
                id: `zone-${zoneId}`,
                type: "zoneBand",
                position: { x: minX - ZONE_PAD_X, y: minY - ZONE_PAD_TOP },
                data: {
                    label: zone.label,
                    color: zone.color,
                    border: zone.border,
                    width: maxX - minX + ZONE_PAD_X * 2,
                    height: maxY - minY + ZONE_PAD_TOP + ZONE_PAD_BOTTOM,
                },
                draggable: false,
                selectable: false,
                connectable: false,
                zIndex: -1,
            };
        });

        const edges = suggestion.relationships.map((r, i) => ({
            id: `${r.source_key}-${r.destination_key}-${i}`,
            source: r.source_key,
            target: r.destination_key,
            type: "smoothstep",
            pathOptions: { borderRadius: 12 },
            style: { stroke: "#1e3a5f", strokeWidth: 2 },
        }));

        return { nodes: [...zoneNodes, ...deviceNodes], edges };
    }, [suggestion]);

    const handleCreate = () => {
        if (!suggestion || !name.trim()) return;
        setIsCreating(true);

        dispatch(
            createDesign({
                name: name.trim(),
                template_id: "safe_enterprise_campus",
                template_scale: suggestion.scale,
            })
        ).then(async (action) => {
            const designId = action.payload?.id;
            if (!designId) {
                setIsCreating(false);
                return;
            }

            const detail = await dispatch(fetchDesignDetail(designId)).unwrap();
            const versionId = detail.versions[0]?.id;
            if (!versionId) {
                setIsCreating(false);
                navigate(`/design-configuration/designs/${designId}`);
                return;
            }

            const version = await dispatch(fetchVersionDetail(versionId)).unwrap();

            // Apply each suggested mapping by matching on label - the labels
            // the template just generated (e.g. "Perimeter Firewall") are the
            // same ones the suggestion preview used, and unique within one
            // applied template, so this reliably lines a real component id up
            // with the asset suggested for it.
            const mappings = suggestion.components.filter((c) => c.suggested_asset_id);
            for (const suggested of mappings) {
                const realComponent = version.components.find((c) => c.label === suggested.label);
                if (realComponent) {
                    await dispatch(
                        mapComponentToAsset({ componentId: realComponent.id, assetId: suggested.suggested_asset_id })
                    );
                }
            }

            setIsCreating(false);
            navigate(`/design-configuration/versions/${versionId}`);
        });
    };

    if (isLoading && !suggestion) {
        return <div className="dc-container"><div className="dc-empty">Loading suggestion…</div></div>;
    }

    return (
        <div className="dc-canvas-page">
            <div className="dc-canvas-toolbar">
                <div className="dc-toolbar-info">
                    {suggestion && (
                        <>
                            {suggestion.scale_label} · {suggestion.total_assets} asset(s) in inventory ·{" "}
                            {suggestion.matched_assets} matched to a slot below
                        </>
                    )}
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                        placeholder="Design name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        style={{ padding: "8px 10px", border: "1px solid #e5e7eb", borderRadius: 6, fontSize: 13 }}
                    />
                    <button
                        className="dc-btn dc-btn-primary"
                        onClick={handleCreate}
                        disabled={!name.trim() || isCreating || !suggestion}
                    >
                        <i className="fa-solid fa-wand-magic-sparkles" /> {isCreating ? "Creating…" : "Create this design"}
                    </button>
                </div>
            </div>

            {error && <div className="dc-toast dc-toast-error">{error}</div>}

            <p className="dc-modal-hint" style={{ margin: "0 0 12px" }}>
                A standard Cisco SAFE campus design sized to your real asset count. Solid boxes are matched to a real
                asset already in your inventory; dashed gray boxes have no matching asset yet and will be created as
                placeholders you can map later.
            </p>

            <div className="dc-canvas-body">
                <div className="dc-canvas-wrap" style={{ width: "100%" }}>
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        nodeTypes={NODE_TYPES}
                        nodesDraggable={false}
                        nodesConnectable={false}
                        elementsSelectable={false}
                        fitView
                        proOptions={{ hideAttribution: true }}
                    >
                        <Background gap={20} color="#e5e7eb" />
                        <Controls showInteractive={false} />
                        <Panel position="bottom-left">
                            <div
                                style={{
                                    display: "flex", flexWrap: "wrap", gap: "6px 14px",
                                    padding: "8px 12px", background: "rgba(255,255,255,0.94)",
                                    border: "1px solid #e5e7eb", borderRadius: 8, fontSize: 11, color: "#4b5563",
                                }}
                            >
                                {Object.entries(ZONES).map(([id, zone]) => (
                                    <span key={id} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                                        <span style={{
                                            width: 10, height: 10, borderRadius: 3, background: zone.color,
                                            border: `1.5px dashed ${zone.border}`, display: "inline-block",
                                        }} />
                                        {zone.label}
                                    </span>
                                ))}
                            </div>
                        </Panel>
                    </ReactFlow>
                </div>
            </div>
        </div>
    );
};

export default SuggestedDesign;
