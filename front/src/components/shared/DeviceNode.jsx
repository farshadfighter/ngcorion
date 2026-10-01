import { Handle, Position } from "@xyflow/react";
import AssetIcon from "./AssetIcon.jsx";
import "../../assets/AssetIcons.css";
import { defaultPortsForType } from "../../utils/devicePorts.js";
import { t } from "../../i18n";

const PORT_HANDLE_STYLE = { width: 7, height: 7, background: "#1e3a5f", border: "1.5px solid #fff" };
const GENERIC_HANDLE_STYLE = { width: 8, height: 8, background: "#1e3a5f", opacity: 0.55 };

// Shared React Flow node used by the Topology, Design & Configuration, Suggested Design and NOC
// canvases: the asset's icon tile with its name, address and vendor/OS badge underneath.
//
// data:
//   label       name under the icon
//   icon        icon key (server-resolved for assets; a component type in Design)
//   typeName    asset type name - only picks the port catalog (utils/devicePorts.js)
//   subtitle    IP address / mapped asset, in monospace
//   badge       short vendor / OS label
//   planned     dashed hollow tile (a design device not built yet); `dashed` is the old name
//   status      "up" | "down" live-status dot (NOC)
//   portCount   real port count, shown as text
//   showPortHandles  false on read-only canvases
//
// One connection handle per known port (EVE-NG style - drag directly from a specific numbered
// port to a port on another device), falling back to 4 generic handles for asset types with no
// known port catalog, or when `showPortHandles` is false. Port handles need ~9px each, so a
// 48-port switch is wider than other nodes; read-only canvases skip them to keep nodes compact.
export function DeviceNode({ data, selected }) {
    const {
        label, icon, typeName, subtitle, badge, status, portCount,
        planned = false, dashed = false, showPortHandles = true,
    } = data;
    const ports = showPortHandles ? defaultPortsForType(typeName || icon, portCount) : [];
    const width = ports.length > 0 ? Math.max(112, ports.length * 9) : 112;
    const displayPortCount = portCount ?? ports.length;

    return (
        <div className={`device-node ${selected ? "selected" : ""}`} style={{ width }}>
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
            <AssetIcon icon={icon || typeName} planned={planned || dashed} status={status} />
            <div className="device-node-label">{label}</div>
            {subtitle && <div className="device-node-sub">{subtitle}</div>}
            {badge && <div className="device-node-badge">{badge}</div>}
            {displayPortCount > 0 && <div className="device-node-ports">{t("{{displayPortCount}} ports", { displayPortCount })}</div>}
        </div>
    );
}

export default DeviceNode;
