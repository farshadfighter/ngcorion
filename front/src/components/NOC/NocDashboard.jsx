import { useEffect, useMemo } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { ReactFlow, Background, Controls } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DEVICE_NODE_TYPES from "../shared/deviceNodeTypes.js";
import { fetchHosts, pollAllNow, clearMessages } from "../../store/nocSlice.jsx";
import { fetchTopology } from "../../store/topologySlice.jsx";
import "../../assets/Noc.css";

const GRID_COLUMNS = 6;
const GRID_SPACING_X = 200;
const GRID_SPACING_Y = 150;

function gridPosition(index) {
    return {
        x: (index % GRID_COLUMNS) * GRID_SPACING_X + 40,
        y: Math.floor(index / GRID_COLUMNS) * GRID_SPACING_Y + 40,
    };
}

// Node border color reflects live SNMP status, independent of device type
// color (DeviceIcon already colors the glyph itself) - green/red/gray ring
// around the same device pictogram Topology and Design use.
const STATUS_COLOR = { up: "#10b981", down: "#ef4444", unmonitored: "#9ca3af" };

export const NocDashboard = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { hosts, isPolling, error, successMessage } = useSelector((state) => state.noc);
    const { nodes: topologyNodes, links: topologyLinks } = useSelector((state) => state.topology);

    useEffect(() => {
        dispatch(fetchHosts());
        dispatch(fetchTopology());
    }, [dispatch]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const stats = useMemo(() => {
        const reachable = hosts.filter((h) => h.has_credential && h.reachable === true).length;
        const unreachable = hosts.filter((h) => h.has_credential && h.reachable === false).length;
        const unmonitored = hosts.filter((h) => !h.has_credential).length;
        return { total: hosts.length, reachable, unreachable, unmonitored };
    }, [hosts]);

    const hostsById = useMemo(() => {
        const map = new Map();
        hosts.forEach((h) => map.set(h.asset_id, h));
        return map;
    }, [hosts]);

    const { flowNodes, flowEdges } = useMemo(() => {
        const nodes = (topologyNodes || []).map((node, index) => {
            const host = hostsById.get(node.id);
            const statusKey = !host || !host.has_credential ? "unmonitored" : host.reachable ? "up" : "down";
            return {
                id: String(node.id),
                type: "device",
                position:
                    node.pos_x != null && node.pos_y != null
                        ? { x: node.pos_x, y: node.pos_y }
                        : gridPosition(index),
                data: {
                    label: node.name,
                    typeName: node.type_name,
                    subtitle: node.ip_address || undefined,
                    portCount: node.port_count,
                    color: STATUS_COLOR[statusKey],
                },
                draggable: false,
            };
        });
        const edges = (topologyLinks || []).map((link) => ({
            id: String(link.id),
            source: String(link.source_asset_id),
            target: String(link.destination_asset_id),
            style: { stroke: "#94a3b8", strokeWidth: 1.5 },
        }));
        return { flowNodes: nodes, flowEdges: edges };
    }, [topologyNodes, topologyLinks, hostsById]);

    const handleNodeClick = (_event, node) => {
        navigate(`/noc/hosts/${node.id}`);
    };

    return (
        <div className="noc-container">
            <div className="noc-toolbar">
                <div className="noc-toolbar-info">SNMP status across every asset, and the same topology graph as Topology.</div>
                <button className="noc-btn noc-btn-primary" onClick={() => dispatch(pollAllNow())} disabled={isPolling}>
                    <i className="fa-solid fa-arrows-rotate" /> {isPolling ? "Polling…" : "Poll All Now"}
                </button>
            </div>

            {(error || successMessage) && (
                <div className={`noc-toast ${error ? "noc-toast-error" : "noc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="noc-stats">
                <div className="noc-stat-card">
                    <div className="noc-stat-value">{stats.total}</div>
                    <div className="noc-stat-label">Total Assets</div>
                </div>
                <div className="noc-stat-card reachable">
                    <div className="noc-stat-value">{stats.reachable}</div>
                    <div className="noc-stat-label">Reachable</div>
                </div>
                <div className="noc-stat-card unreachable">
                    <div className="noc-stat-value">{stats.unreachable}</div>
                    <div className="noc-stat-label">Unreachable</div>
                </div>
                <div className="noc-stat-card unmonitored">
                    <div className="noc-stat-value">{stats.unmonitored}</div>
                    <div className="noc-stat-label">Not Monitored</div>
                </div>
            </div>

            <div className="noc-graph-wrap">
                <ReactFlow
                    nodes={flowNodes}
                    edges={flowEdges}
                    nodeTypes={DEVICE_NODE_TYPES}
                    nodesDraggable={false}
                    nodesConnectable={false}
                    onNodeClick={handleNodeClick}
                    fitView
                    proOptions={{ hideAttribution: true }}
                >
                    <Background gap={20} color="#e5e7eb" />
                    <Controls showInteractive={false} />
                </ReactFlow>
            </div>

            <div className="noc-table-container">
                {hosts.length === 0 ? (
                    <div className="noc-empty">No assets yet.</div>
                ) : (
                    <table className="noc-table">
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Asset</th>
                                <th>Type</th>
                                <th>IP Address</th>
                                <th>SNMP sysName</th>
                                <th>Last Polled</th>
                            </tr>
                        </thead>
                        <tbody>
                            {hosts.map((h) => {
                                const statusKey = !h.has_credential ? "unmonitored" : h.reachable ? "up" : "down";
                                return (
                                    <tr key={h.asset_id} className="clickable" onClick={() => navigate(`/noc/hosts/${h.asset_id}`)}>
                                        <td><span className={`noc-status-dot ${statusKey}`} />{statusKey === "unmonitored" ? "Not monitored" : statusKey === "up" ? "Up" : "Down"}</td>
                                        <td>{h.asset_name}</td>
                                        <td>{h.asset_type_name || "—"}</td>
                                        <td>{h.ip_address || "—"}</td>
                                        <td>{h.sys_name || "—"}</td>
                                        <td>{h.last_polled_at ? new Date(h.last_polled_at).toLocaleString() : "—"}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};

export default NocDashboard;
