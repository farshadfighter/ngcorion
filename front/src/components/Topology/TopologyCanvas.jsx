/**
 * Topology canvas (React Flow): assets as nodes, links as edges, draggable positions; and the
 * external networks (the Internet, MPLS, a WAN, a public cloud ...) as nodes "c-<id>" with the devices'
 * connections to them as edges "cl-<id>".
 */
import { useEffect, useMemo, useCallback } from "react";
import { ReactFlow, Background, Controls, MiniMap, Panel, useNodesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";
import IconLegend from "../shared/IconLegend.jsx";
import { iconLabel } from "../shared/assetIcons.js";
import { t } from "../../i18n";
import { defaultPortsForType, portKey } from "../../utils/devicePorts.js";

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
    // Computed at read time from Asset.hosted_on_asset_id, not a real
    // TopologyLink - see TopologyService.get_hosted_edges. Always dashed,
    // regardless of status, so it reads as logical rather than cabled.
    hosted: "#9333ea",
    // a device's connection to an external network (the "external" icon family's colour)
    external: "#0f766e",
};

const CLOUD = "c-";
const cloudNodeId = (id) => `${CLOUD}${id}`;
const isCloud = (nodeId) => String(nodeId).startsWith(CLOUD);
const cloudIdOf = (nodeId) => Number(String(nodeId).slice(CLOUD.length));

// A cloud never dragged sits in a row above the devices.
function cloudPosition(index) {
    return { x: index * GRID_SPACING_X + 40, y: -GRID_SPACING_Y + 40 };
}

export function TopologyCanvas({
    nodes, links, clouds = [], cloudLinks = [], onConnect, onEdgeClick, onNodeDragStop,
    onConnectCloud, onCloudClick, onCloudLinkClick, onCloudDragStop,
}) {
    const [flowNodes, setFlowNodes, onNodesChange] = useNodesState([]);
    // a cloud added, removed, renamed or of another kind redraws; a drag does not
    const cloudsShape = clouds.map((c) => `${c.id}:${c.kind}:${c.label}:${c.provider || ""}`).join("|");

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
                    icon: node.icon,
                    typeName: node.type_name,
                    subtitle: node.ip_address || node.hostname || undefined,
                    badge: node.icon_badge || undefined,
                    portCount: node.port_count,
                    ports: node.interfaces?.length ? node.interfaces : undefined,
                },
            })).concat(clouds.map((cloud, index) => ({
                id: cloudNodeId(cloud.id),
                type: "device",
                position:
                    cloud.pos_x != null && cloud.pos_y != null
                        ? { x: cloud.pos_x, y: cloud.pos_y }
                        : cloudPosition(index),
                data: {
                    label: cloud.label,
                    icon: cloud.kind,
                    typeName: iconLabel(cloud.kind),
                    subtitle: cloud.provider || iconLabel(cloud.kind),
                    showPortHandles: false,
                },
            })))
        );
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [nodes.length, cloudsShape]);

    // The ports each node draws: the device's real ones when the NOC polls it, else its catalog. A link
    // anchors on the same port (also spelled long or short: "GigabitEthernet1/0/24" = "Gi1/0/24"), else
    // on the catalog port with the same number, else on the node's first handle.
    const handles = useMemo(() => {
        const out = {};
        for (const node of nodes) {
            out[node.id] = node.interfaces?.length ? node.interfaces
                : defaultPortsForType(node.type_name || node.icon, node.port_count);
        }
        return out;
    }, [nodes]);
    const handleOf = (assetId, port) => {
        const ports = handles[assetId] || [];
        if (!port || !ports.length) return undefined;
        if (ports.includes(port)) return port;
        const key = portKey(port);
        const same = ports.find((p) => portKey(p) === key);
        if (same) return same;
        const num = /(\d+)$/.exec(port)?.[1];
        return num ? ports.find((p) => /(\d+)$/.exec(p)?.[1] === num) : undefined;
    };

    const flowEdges = useMemo(
        () =>
            links.map((link) => ({
                id: String(link.id),
                source: String(link.source_asset_id),
                target: String(link.destination_asset_id),
                sourceHandle: handleOf(link.source_asset_id, link.source_interface),
                targetHandle: handleOf(link.destination_asset_id, link.destination_interface),
                label: link.vlan ? t("VLAN {{vlan}}", { vlan: link.vlan }) : undefined,
                type: "smoothstep",
                pathOptions: { borderRadius: 8 },
                style: {
                    stroke: link.missing_since ? "#dc2626" : LINK_TYPE_COLOR[link.link_type] || "#1e3a5f",
                    strokeWidth: link.missing_since ? 2.5 : 2,
                    strokeDasharray: link.missing_since ? "6 4"
                        : link.status === "planned" || link.link_type === "hosted" ? "5 4" : undefined,
                    opacity: link.status === "down" ? 0.4 : 1,
                },
                data: { link },
            })).concat(cloudLinks.map((cl) => ({
                id: `cl-${cl.id}`,
                source: cloudNodeId(cl.cloud_id),
                target: String(cl.asset_id),
                targetHandle: handleOf(cl.asset_id, cl.interface),
                label: cl.circuit_id || undefined,
                type: "smoothstep",
                pathOptions: { borderRadius: 8 },
                style: {
                    stroke: LINK_TYPE_COLOR.external,
                    strokeWidth: 2,
                    strokeDasharray: cl.status === "planned" ? "5 4" : undefined,
                    opacity: cl.status === "down" ? 0.4 : 1,
                },
                data: { cloudLink: cl },
            }))),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [links, cloudLinks, handles]
    );

    const handleConnect = useCallback(
        (connection) => {
            const [src, dst] = [connection.source, connection.target];
            if (isCloud(src) || isCloud(dst)) {
                if (isCloud(src) && isCloud(dst)) return;           // two external networks: nothing to draw
                const device = isCloud(src) ? dst : src;
                onConnectCloud?.({
                    cloud_id: cloudIdOf(isCloud(src) ? src : dst),
                    asset_id: Number(device),
                    interface: (isCloud(src) ? connection.targetHandle : connection.sourceHandle) || null,
                });
                return;
            }
            if (!onConnect) return;
            onConnect({
                source_asset_id: Number(connection.source),
                destination_asset_id: Number(connection.target),
                source_interface: connection.sourceHandle || null,
                destination_interface: connection.targetHandle || null,
            });
        },
        [onConnect, onConnectCloud]
    );

    const handleEdgeClick = useCallback(
        (_event, edge) => {
            if (edge.data.cloudLink) onCloudLinkClick?.(edge.data.cloudLink);
            else onEdgeClick?.(edge.data.link);
        },
        [onEdgeClick, onCloudLinkClick]
    );

    const handleNodeClick = useCallback(
        (_event, node) => {
            if (isCloud(node.id)) onCloudClick?.(cloudIdOf(node.id));
        },
        [onCloudClick]
    );

    const handleNodeDragStop = useCallback(
        (_event, node) => {
            if (isCloud(node.id)) onCloudDragStop?.(cloudIdOf(node.id), node.position.x, node.position.y);
            else onNodeDragStop?.(Number(node.id), node.position.x, node.position.y);
        },
        [onNodeDragStop, onCloudDragStop]
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
                onNodeClick={handleNodeClick}
                fitView
                proOptions={{ hideAttribution: true }}
            >
                <Background gap={20} color="#e5e7eb" />
                <Controls />
                <MiniMap pannable zoomable style={{ background: "#f9fafb" }} />
                <Panel position="top-left">
                    <IconLegend />
                </Panel>
            </ReactFlow>
        </div>
    );
}

export default TopologyCanvas;
