// Mirrors app/modules/design/templates.py's ZONES dict exactly, so the
// zone bands drawn behind Suggested Design's nodes use the same id/label
// pairing the backend already assigns each component to - same convention
// as DeviceIcon.jsx mirroring hosting.py's keyword rules.
export const ZONES = {
    internet_edge: { label: "Internet Edge", color: "#eef2ff", border: "#c7d2fe" },
    dmz: { label: "DMZ", color: "#fff7ed", border: "#fed7aa" },
    core: { label: "Core", color: "#eef6ff", border: "#bfdbfe" },
    distribution: { label: "Distribution", color: "#ecfdf5", border: "#a7f3d0" },
    access: { label: "Access", color: "#f0fdf4", border: "#bbf7d0" },
    data_center: { label: "Data Center", color: "#fdf4ff", border: "#e9d5ff" },
};

export default ZONES;
