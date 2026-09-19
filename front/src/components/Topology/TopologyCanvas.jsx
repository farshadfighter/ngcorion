import { useMemo, useCallback } from "react";
import { ReactFlow, Background, Controls, MiniMap } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";

const GRID_COLUMNS = 5;
const GRID_SPACING_X = 220;
const GRID_SPACING_Y = 160;

// No position is stored server-side (nodes are Asset rows, not a design
// canvas), so nodes are laid out on a simple grid every render. Dragging a
// node moves it on screen but isn't persisted - that's fine, the graph is
// read again fresh from the backend on every visit.
function gridPosition(index) {
    return {
        x: (index % GRID_COLUMNS) * GRID_SPACING_X + 40,
        y: Math.floor(index / GRID_COLUMNS) * GRID_SPACING_Y + 40,
    };
}

const LINK_TYPE_COLOR = {
    ethernet: "#1e3a5f",
    fiber: "#0891b2",
    wireless: "#7c3aed",
    logical: "#9ca3af",
};

export function TopologyCanvas({ nodes, links, onConnect, onEdgeClick }) {
    const flowNodes = useMemo(
        () =>
            nodes.map((node, index) => ({
                id: String(node.id),
                type: "device",
                position: gridPosition(index),
                data: {
                    label: node.name,
                    typeName: node.type_name,
                    subtitle: node.ip_address || node.hostname || undefined,
                },
            })),
        [nodes]
    );

    const flowEdges = useMemo(
        () =>
            links.map((link) => ({
                id: String(link.id),
                source: String(link.source_asset_id),
                target: String(link.destination_asset_id),
                sourceHandle: link.source_interface || undefined,
                targetHandle: link.destination_interface || undefined,
                label: link.vlan ? `VLAN ${link.vlan}` : undefined,
                style: {
                    stroke: LINK_TYPE_COLOR[link.link_type] || "#1e3a5f",
                    strokeWidth: 2,
                    strokeDasharray: link.status === "planned" ? "5 4" : undefined,
                    opacity: link.status === "down" ? 0.4 : 1,
                },
                data: { link },
            })),
        [links]
    );

    const handleConnect = useCallback(
        (connection) => {
            if (!onConnect) return;
            onConnect({
                source_asset_id: Number(connection.source),
                destination_asset_id: Number(connection.target),
                source_interface: connection.sourceHandle || null,
                destination_interface: connection.targetHandle || null,
            });
        },
        [onConnect]
    );

    const handleEdgeClick = useCallback(
        (_event, edge) => {
            onEdgeClick?.(edge.data.link);
        },
        [onEdgeClick]
    );

    return (
        <div style={{ width: "100%", height: "100%" }}>
            <ReactFlow
                nodes={flowNodes}
                edges={flowEdges}
                nodeTypes={DEVICE_NODE_TYPES}
                onConnect={handleConnect}
                onEdgeClick={handleEdgeClick}
                fitView
                proOptions={{ hideAttribution: true }}
            >
                <Background gap={20} color="#e5e7eb" />
                <Controls />
                <MiniMap pannable zoomable style={{ background: "#f9fafb" }} />
            </ReactFlow>
        </div>
    );
}

export default TopologyCanvas;
