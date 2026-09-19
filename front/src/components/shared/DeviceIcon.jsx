// EVE-NG-style device pictograms shared by the Topology and Design & Configuration canvases: a
// flat device-shaped chassis with a small distinguishing glyph and a row of port ticks, so a
// device reads as real network hardware rather than a plain labeled box. ngcorion's asset types
// are free text (no fixed code list, see app/models/asset.py's asset_type_id -> asset_types.type_name),
// so the glyph is picked by keyword match against the type name rather than an exact code.

function Chassis({ size, color, strokeWidth, tall = false, children }) {
    const w = 20;
    const h = tall ? 22 : 14;
    const x = (24 - w) / 2;
    const y = tall ? 1 : (24 - h) / 2 - 1;
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
            <rect x={x} y={y} width={w} height={h} rx={2.5} stroke={color} strokeWidth={strokeWidth} />
            {children}
        </svg>
    );
}

function PortRow({ count, y, color }) {
    const startX = 5;
    const endX = 19;
    const step = count > 1 ? (endX - startX) / (count - 1) : 0;
    return (
        <>
            {Array.from({ length: count }, (_, i) => (
                <rect key={i} x={startX + step * i - 0.7} y={y} width={1.4} height={2} fill={color} stroke="none" />
            ))}
        </>
    );
}

const RouterGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        <path d="M7 12a5 5 0 0 1 8-4" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <path d="M9.5 6.5 7 8l0.5-3" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
        <path d="M17 12a5 5 0 0 1-8 4" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <path d="M14.5 17.5 17 16l-0.5 3" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
        <PortRow count={4} y={16.5} color={color} />
    </Chassis>
);

const SwitchGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        <path d="M6 9h9" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <path d="M12.5 6.5 15 9l-2.5 2.5" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
        <path d="M18 13H9" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <path d="M11.5 10.5 9 13l2.5 2.5" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
        <PortRow count={8} y={16.5} color={color} />
    </Chassis>
);

const FirewallGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        {[7, 10.3, 13.6].map((y, row) => (
            <path key={y} d={row % 2 === 0 ? `M6 ${y}h5.5M13 ${y}h5` : `M6 ${y}h2.5M10 ${y}h8`} stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        ))}
        <PortRow count={4} y={16.5} color={color} />
    </Chassis>
);

const ServerGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth} tall>
        <path d="M6 6.5h12" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <path d="M6 11h12" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <circle cx={8} cy={4} r={0.6} fill={color} stroke="none" />
        <circle cx={8} cy={8.75} r={0.6} fill={color} stroke="none" />
        <PortRow count={2} y={20} color={color} />
    </Chassis>
);

const LoadBalancerGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        <path d="M12 6v8M8 10.5l4-2.5 4 2.5" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
        <path d="M6 14h2.5M11 14h2M15.5 14H18" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <PortRow count={4} y={16.5} color={color} />
    </Chassis>
);

const WirelessGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        <path d="M8.5 11a5 5 0 0 1 7 0" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <path d="M10 13a2.7 2.7 0 0 1 4 0" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" />
        <circle cx={12} cy={15} r={0.7} fill={color} stroke="none" />
        <PortRow count={2} y={17.2} color={color} />
    </Chassis>
);

const StorageGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth} tall>
        <ellipse cx={12} cy={5.5} rx={6} ry={1.8} stroke={color} strokeWidth={strokeWidth} />
        <path d="M6 5.5v13c0 1 2.7 1.8 6 1.8s6-.8 6-1.8v-13" stroke={color} strokeWidth={strokeWidth} />
        <path d="M6 11c0 1 2.7 1.8 6 1.8s6-.8 6-1.8" stroke={color} strokeWidth={strokeWidth} />
    </Chassis>
);

const CloudGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        <path
            d="M8.2 12.6a2.2 2.2 0 0 1 .2-4.4 2.7 2.7 0 0 1 5.1-1 2 2 0 0 1 2.5 1.9 1.9 1.9 0 0 1-.3 3.5z"
            stroke={color}
            strokeWidth={strokeWidth * 0.85}
            strokeLinejoin="round"
        />
        <PortRow count={4} y={16.5} color={color} />
    </Chassis>
);

const GenericGlyph = ({ size, color, strokeWidth }) => (
    <Chassis size={size} color={color} strokeWidth={strokeWidth}>
        <rect x={9.5} y={8.5} width={5} height={5} rx={0.6} stroke={color} strokeWidth={strokeWidth} />
        <PortRow count={4} y={16.5} color={color} />
    </Chassis>
);

// Ordered keyword -> glyph rules, checked against the asset type's name (lowercased). First
// match wins, so more specific keywords should come before broader ones.
const KEYWORD_RULES = [
    [/firewall|fortigate|fortinet|palo ?alto|asa/, FirewallGlyph],
    [/router|cisco.*ios|gateway/, RouterGlyph],
    [/switch/, SwitchGlyph],
    [/load ?balanc/, LoadBalancerGlyph],
    [/wireless|wifi|access point|\bap\b|wlc/, WirelessGlyph],
    [/storage|\bnas\b|\bsan\b/, StorageGlyph],
    [/cloud/, CloudGlyph],
    [/server|linux|windows|apache|mongo|mssql|sql|database|\bdb\b/, ServerGlyph],
];

function glyphForType(typeName) {
    if (!typeName) return GenericGlyph;
    const lower = String(typeName).toLowerCase();
    for (const [pattern, glyph] of KEYWORD_RULES) {
        if (pattern.test(lower)) return glyph;
    }
    return GenericGlyph;
}

// Calls the glyph as a plain function (not as a `<Component />`) - these glyphs are stateless
// pure functions, so this sidesteps the "component created during render" lint rule, which
// exists to guard against dynamic components that hold their own state.
export function DeviceIcon({ typeName, size = 20, color = "#334155", strokeWidth = 1.6 }) {
    return glyphForType(typeName)({ size, color, strokeWidth });
}

export default DeviceIcon;
