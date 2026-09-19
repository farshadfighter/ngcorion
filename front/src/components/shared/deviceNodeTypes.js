import DeviceNode from "./DeviceNode.jsx";

// Kept in its own file (not exported alongside the DeviceNode component) so DeviceNode.jsx can
// stay component-only for Vite's fast-refresh boundary.
export const DEVICE_NODE_TYPES = { device: DeviceNode };

export default DEVICE_NODE_TYPES;
