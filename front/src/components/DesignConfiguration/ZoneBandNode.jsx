// A non-interactive React Flow node rendered behind the device nodes it
// bounds, so the SAFE zones the layout already positions components into
// (see app/modules/design/templates.py) are also visible at a glance
// instead of only implied by where boxes happen to sit. Given a low
// zIndex by the canvas that places it (see SuggestedDesign.jsx), so real
// device nodes always draw on top of it.
export function ZoneBandNode({ data }) {
    const { label, width, height, color, border } = data;
    return (
        <div
            style={{
                width,
                height,
                borderRadius: 14,
                background: color,
                border: `1.5px dashed ${border}`,
                boxSizing: "border-box",
            }}
        >
            <div
                style={{
                    padding: "8px 12px",
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: "0.04em",
                    textTransform: "uppercase",
                    color: "#6b7280",
                }}
            >
                {label}
            </div>
        </div>
    );
}

export default ZoneBandNode;
