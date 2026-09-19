import { useEffect, useMemo, useCallback } from "react";
import { ReactFlow, Background, Controls, MiniMap, useNodesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";

const GRID_COLUMNS = 5;
const GRID_SPACING_X = 220;
const GRID_SPACING_Y = 160;

// A node that has never been dragged (pos_x/pos_y both null - see
// TopologyNode schema) falls back to a simple grid slot. Once dragged, its
// saved position (app/models/topology.py::TopologyNodePosition) is used
// instead, and stays fixed until dragged again.
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

export function TopologyCanvas({ nodes, links, onConnect, onEdgeClick, onNodeDragStop }) {
    const [flowNodes, setFlowNodes, onNodesChange] = useNodesState([]);

    // Rebuild from redux whenever the node list changes shape (assets
    // added/removed) - live drag position is handled locally by
    // useNodesState and only pushed back to redux (and the backend) on drag
    // stop, same pattern as DesignCanvas.
    useEffect(() => {
        setFlowNodes(
            nodes.map((node, index) => ({
                id: String(node.id),
                type: "device",
                position:
                    node.pos_x != null && node.pos_y != null
                        ? { x: node.pos_x, y: node.pos_y }
                        : gridPosition(index),
                data: {
                    label: node.name,
                    typeName: node.type_name,
                    subtitle: node.ip_address || node.hostname || undefined,
                    portCount: node.port_count,
                },
            }))
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [nodes.length]);

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

    const handleNodeDragStop = useCallback(
        (_event, node) => {
            onNodeDragStop?.(Number(node.id), node.position.x, node.position.y);
        },
        [onNodeDragStop]
    );

    return (
        <div style={{ width: "100%", height: "100%" }}>
            <ReactFlow
                nodes={flowNodes}
                edges={flowEdges}
                nodeTypes={DEVICE_NODE_TYPES}
                onNodesChange={onNodesChange}
                onNodeDragStop={handleNodeDragStop}
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
