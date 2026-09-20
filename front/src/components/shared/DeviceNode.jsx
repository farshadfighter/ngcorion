import { Handle, Position } from "@xyflow/react";
import DeviceIcon from "./DeviceIcon.jsx";
import { defaultPortsForType } from "../../utils/devicePorts.js";

const PORT_HANDLE_STYLE = { width: 7, height: 7, background: "#1e3a5f", border: "1.5px solid #fff" };
const GENERIC_HANDLE_STYLE = { width: 8, height: 8, background: "#1e3a5f" };

// Shared React Flow node used by both the Topology and Design & Configuration canvases: one
// real connection handle per known port (EVE-NG style - drag directly from a specific numbered
// port on one device to a specific port on another), falling back to 4 generic handles for
// asset types with no known port catalog (see utils/devicePorts.js).
export function DeviceNode({ data, selected }) {
    const { label, typeName, color = "#1e3a5f", dashed = false, subtitle, portCount } = data;
    const ports = defaultPortsForType(typeName, portCount);
    const minWidth = ports.length > 0 ? Math.max(110, ports.length * 9) : 110;

    return (
        <div
            style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: 4,
                padding: "10px 14px",
                borderRadius: 10,
                border: `2px ${dashed ? "dashed" : "solid"} ${color}`,
                background: dashed ? "#fff" : `${color}14`,
                boxShadow: selected ? `0 0 0 3px ${color}33` : "0 1px 2px rgba(0,0,0,0.08)",
                minWidth,
                cursor: "pointer",
            }}
        >
            {ports.length > 0 ? (
                // A physical port can be either end of a link, so each one needs both
                // a source and a target handle at the same id/position - React Flow
                // keys its internal handle registry by (nodeId, handleId, type), so a
                // source-only handle silently fails to resolve the edge's endpoint
                // position whenever this node is used as the link's target.
                ports.flatMap((port, i) => {
                    const style = { ...PORT_HANDLE_STYLE, left: `${((i + 0.5) / ports.length) * 100}%` };
                    return [
                        <Handle key={`${port}-target`} id={port} type="target" position={Position.Bottom} style={style} />,
                        <Handle key={`${port}-source`} id={port} type="source" position={Position.Bottom} style={style} title={port} />,
                    ];
                })
            ) : (
                <>
                    <Handle type="target" position={Position.Left} style={GENERIC_HANDLE_STYLE} />
                    <Handle type="target" position={Position.Top} style={GENERIC_HANDLE_STYLE} />
                    <Handle type="source" position={Position.Right} style={GENERIC_HANDLE_STYLE} />
                    <Handle type="source" position={Position.Bottom} style={GENERIC_HANDLE_STYLE} />
                </>
            )}
            <DeviceIcon typeName={typeName} color={color} size={22} />
            <div style={{ fontSize: 12, fontWeight: 600, textAlign: "center", lineHeight: 1.25, color: "#1f2937" }}>{label}</div>
            {subtitle && <div style={{ fontSize: 10, color: "#6b7280" }}>{subtitle}</div>}
            {ports.length > 0 && <div style={{ fontSize: 9, color: "#9ca3af" }}>{ports.length} ports</div>}
        </div>
    );
}

export default DeviceNode;
