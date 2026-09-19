// Default port/interface catalog per device type keyword, used to offer a real port to drag a
// cable from on the Topology and Design & Configuration canvases. Purely a frontend convenience
// list (ngcorion's own `ports` table is nmap-discovered *service* ports like 22/443, not
// physical switch interfaces, so it isn't reused here) - the port name picked is stored as free
// text on the link (TopologyLink.source_interface/destination_interface).
const PORT_RULES = [
    [/firewall|fortigate|fortinet|palo ?alto|asa/, ["port1", "port2", "port3", "port4", "port5", "port6", "port7", "port8"]],
    [/router|cisco.*ios|gateway/, ["Gi0/0", "Gi0/1", "Gi0/2", "Gi0/3"]],
    [/switch/, Array.from({ length: 24 }, (_, i) => `Gi0/${i + 1}`)],
    [/load ?balanc/, ["Gi0/0", "Gi0/1"]],
    [/wireless|wifi|access point|\bap\b|wlc/, ["Gi0/0", "Gi0/1"]],
    [/server|linux|windows|apache|mongo|mssql|sql|database|\bdb\b/, ["eth0", "eth1"]],
];

// Naming style per keyword group, reused to generate a custom-length port
// list when the asset has a real port_count (Asset.port_count) instead of
// falling back to the keyword catalog's fixed-length default below.
const PORT_NAME_STYLES = [
    [/firewall|fortigate|fortinet|palo ?alto|asa/, (i) => `port${i + 1}`],
    [/router|cisco.*ios|gateway/, (i) => `Gi0/${i}`],
    [/switch/, (i) => `Gi0/${i + 1}`],
    [/load ?balanc/, (i) => `Gi0/${i}`],
    [/wireless|wifi|access point|\bap\b|wlc/, (i) => `Gi0/${i}`],
    [/server|linux|windows|apache|mongo|mssql|sql|database|\bdb\b/, (i) => `eth${i}`],
];

function namingStyleForType(typeName) {
    const lower = String(typeName || "").toLowerCase();
    for (const [pattern, name] of PORT_NAME_STYLES) {
        if (pattern.test(lower)) return name;
    }
    return (i) => `Port ${i + 1}`;
}

/**
 * @param typeName - asset_type.type_name, used to keyword-match a naming style
 * @param explicitCount - Asset.port_count, when known - overrides the
 *   keyword catalog's fixed default length with however many ports this
 *   specific device actually has.
 */
export function defaultPortsForType(typeName, explicitCount) {
    if (explicitCount != null && explicitCount > 0) {
        const name = namingStyleForType(typeName);
        return Array.from({ length: explicitCount }, (_, i) => name(i));
    }
    if (!typeName) return [];
    const lower = String(typeName).toLowerCase();
    for (const [pattern, ports] of PORT_RULES) {
        if (pattern.test(lower)) return ports;
    }
    return [];
}

export default defaultPortsForType;
