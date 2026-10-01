import { ASSET_ICONS, iconColor, iconKey } from "./assetIcons.js";

const STATUS_DOT = { up: "#22c55e", down: "#ef4444" };

/**
 * One asset icon tile: family colour, white glyph.
 *
 *   planned - drawn dashed and hollow (a design device not built yet)
 *   status  - "up" | "down" adds a live-status dot (NOC)
 *   risk    - "high" | "critical" adds a small risk tag
 */
export function AssetIcon({ icon, size = 44, planned = false, status, risk, title }) {
    const key = iconKey(icon);
    const color = iconColor(key);
    const radius = Math.round(size * 0.25);
    const glyph = Math.round(size * 0.6);
    const dot = STATUS_DOT[status];
    const showRisk = risk === "high" || risk === "critical";
    return (
        <span
            className="asset-icon"
            title={title || ASSET_ICONS[key].label}
            style={{
                position: "relative",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
                width: size,
                height: size,
                borderRadius: radius,
                background: planned ? "#ffffff" : color,
                border: planned ? `2px dashed ${color}` : "none",
                boxShadow: planned ? "none" : "0 1px 2px rgba(15,23,42,.18)",
                boxSizing: "border-box",
            }}
        >
            <svg width={glyph} height={glyph} viewBox="0 0 24 24" fill="none"
                 stroke={planned ? color : "#ffffff"} strokeWidth={size < 28 ? 2 : 1.8}
                 strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d={ASSET_ICONS[key].d} />
            </svg>
            {dot && (
                <span
                    aria-label={status === "down" ? "Unreachable" : "Reachable"}
                    style={{
                        position: "absolute", right: -4, top: -4, width: 12, height: 12,
                        borderRadius: "50%", background: dot, border: "2px solid #fff",
                    }}
                />
            )}
            {showRisk && (
                <span
                    style={{
                        position: "absolute", left: -5, bottom: -5, height: 16, padding: "0 5px",
                        borderRadius: 8, background: "#ea580c", border: "2px solid #fff", color: "#fff",
                        fontSize: 9, fontWeight: 700, lineHeight: "12px", boxSizing: "border-box",
                    }}
                >
                    {risk === "critical" ? "CRIT" : "HIGH"}
                </span>
            )}
        </span>
    );
}

export default AssetIcon;
