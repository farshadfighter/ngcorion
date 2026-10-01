// The asset icon set: colour = family, shape = type. Used by every place an
// asset is drawn (Design, Suggested Design, Topology, NOC, Asset Inventory,
// Backup) so a device looks the same everywhere.
//
// Which icon an *asset* gets is decided on the server (app/core/asset_icons.py:
// override > asset type's icon > keyword rules) and arrives as `icon` /
// `resolved_icon`. The keyword table below mirrors that file's _NAME_RULES and
// is only used where there is no asset yet: the Asset Type form's live
// suggestion and a design component that is not mapped to an asset.

export const ICON_FAMILIES = {
    network: { label: "Network", color: "#1d4ed8" },
    security: { label: "Security", color: "#c2410c" },
    compute: { label: "Compute", color: "#334155" },
    services: { label: "Services", color: "#6d28d9" },
    storage: { label: "Storage", color: "#a16207" },
    endpoints: { label: "Endpoints", color: "#15803d" },
    external: { label: "External", color: "#0f766e" },
    other: { label: "Other", color: "#6b7280" },
};

// Glyphs are drawn on a 24x24 grid as a single stroked path.
export const ASSET_ICONS = {
    router: {
        label: "Router", family: "network",
        d: "M16 12a4 4 0 1 1-8 0a4 4 0 1 1 8 0M9.2 9.2 5.5 5.5M5.5 8.3V5.5h2.8M14.8 14.8l3.7 3.7M18.5 15.7v2.8h-2.8M18.5 5.5l-3.7 3.7M14.8 6.4v2.8h2.8M5.5 18.5l3.7-3.7M9.2 17.6v-2.8H6.4",
    },
    switch: { label: "Switch", family: "network", d: "M5 9h13M15 6l3 3-3 3M19 15H6M9 12l-3 3 3 3" },
    wireless: {
        label: "Wireless AP", family: "network",
        d: "M12 20v-5.5M8.6 11.1a4.8 4.8 0 0 1 6.8 0M6 8.4a8.5 8.5 0 0 1 12 0M12 14.2h.01",
    },
    load_balancer: {
        label: "Load balancer", family: "network",
        d: "M12 4v6M12 10l-6 4.5V19M12 10v9M12 10l6 4.5V19M4 17l2 2 2-2M10 17l2 2 2-2M16 17l2 2 2-2",
    },
    firewall: {
        label: "Firewall", family: "security",
        d: "M4 6h16v12H4zM4 10h16M4 14h16M9 6v4M15 6v4M12 10v4M7 14v4M17 14v4",
    },
    server: {
        label: "Physical server", family: "compute",
        d: "M6 3.5h12v17H6zM6 9.2h12M6 14.8h12M9 6.4h.01M9 12h.01M9 17.7h.01M12.5 6.4h3M12.5 12h3M12.5 17.7h3",
    },
    hypervisor: { label: "Virtual host", family: "compute", d: "M9 4h11v11H9zM6.5 6.5v11h11M4 9v11h11" },
    linux: { label: "Linux server", family: "compute", d: "M3.5 5h17v14h-17zM7 10l3 2.5L7 15M12.5 15h4.5" },
    windows: {
        label: "Windows server", family: "compute",
        d: "M3.5 5h17v14h-17zM3.5 9h17M6.5 7h.01M9 7h.01M7 12.5h10M7 15.5h6",
    },
    web: {
        label: "Web server", family: "services",
        d: "M20 12a8 8 0 1 1-16 0a8 8 0 1 1 16 0M4 12h16M12 4c2.4 2.4 3.4 5 3.4 8s-1 5.6-3.4 8M12 4C9.6 6.4 8.6 9 8.6 12s1 5.6 3.4 8",
    },
    database: {
        label: "Database", family: "services",
        d: "M5.5 6.5c0-1.4 2.9-2.5 6.5-2.5s6.5 1.1 6.5 2.5S15.6 9 12 9 5.5 7.9 5.5 6.5zM5.5 6.5v11c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5v-11M5.5 12c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5",
    },
    storage: {
        label: "Storage", family: "storage",
        d: "M3.5 6h17v5h-17zM3.5 13h17v5h-17zM16.5 8.5h.01M16.5 15.5h.01M6.5 8.5h6M6.5 15.5h6",
    },
    workstation: { label: "Workstation", family: "endpoints", d: "M3.5 4.5h17v11h-17zM9 20h6M12 15.5V20" },
    iot: {
        label: "IoT device", family: "endpoints",
        d: "M8 8h8v8H8zM10.5 4v4M13.5 4v4M10.5 16v4M13.5 16v4M4 10.5h4M4 13.5h4M16 10.5h4M16 13.5h4",
    },
    internet: {
        label: "Internet", family: "external",
        d: "M7 18.5a4.5 4.5 0 0 1-.4-9 6 6 0 0 1 11.3 1.3A3.9 3.9 0 0 1 17.5 18.5z",
    },
    other: {
        label: "Other", family: "other",
        d: "M5 5h14v14H5zM9.6 9.8a2.4 2.4 0 1 1 3.3 2.2c-.6.3-.9.8-.9 1.4v.4M12 16.3h.01",
    },
};

export const ICON_KEYS = Object.keys(ASSET_ICONS);

// Palette / picker order, grouped by family.
export const ICON_GROUPS = Object.keys(ICON_FAMILIES)
    .map((family) => ({
        family,
        ...ICON_FAMILIES[family],
        icons: ICON_KEYS.filter((k) => ASSET_ICONS[k].family === family),
    }))
    .filter((g) => g.icons.length > 0);

// Older design components were saved with these component types.
const ALIASES = { cloud: "internet", loadbalancer: "load_balancer", "load-balancer": "load_balancer" };

// Mirrors _NAME_RULES in app/core/asset_icons.py - keep the two in step.
const NAME_RULES = [
    [/firewall|fortigate|palo ?alto|\basa\b|\butm\b|check ?point|sophos/i, "firewall"],
    [/load ?balanc|\bf5\b|big-?ip|haproxy|\badc\b/i, "load_balancer"],
    [/router|gateway|\bisr\b|\basr\b/i, "router"],
    [/wireless|wi-?fi|access ?point|\bap\b|\bwlc\b/i, "wireless"],
    [/switch|catalyst|nexus/i, "switch"],
    [/hypervisor|esxi|vmware|hyper-?v|proxmox|virtual ?host|vcenter|\bxen/i, "hypervisor"],
    [/database|\bdb\b|mongo|mssql|sql ?server|mysql|postgres|oracle|mariadb|redis/i, "database"],
    [/\bweb|apache|nginx|\biis\b|tomcat/i, "web"],
    [/storage|\bnas\b|\bsan\b|netapp|synology/i, "storage"],
    [/windows|domain ?controller|active ?directory/i, "windows"],
    [/linux|ubuntu|debian|centos|rhel|red ?hat|rocky|alma|suse|fedora/i, "linux"],
    [/workstation|desktop|laptop|\bpc\b|endpoint/i, "workstation"],
    [/\biot\b|camera|cctv|printer|sensor|\bplc\b|scada|voip|ip ?phone/i, "iot"],
    [/internet|\bisp\b|\bwan\b|cloud/i, "internet"],
    [/server|bare ?metal/i, "server"],
];

export function suggestIconFromName(name) {
    if (!name) return "other";
    for (const [pattern, key] of NAME_RULES) {
        if (pattern.test(name)) return key;
    }
    return "other";
}

/** Normalises anything that names an icon - a key from the server, an old
 *  design component type, or a free-text type name - to a known key. */
export function iconKey(value) {
    if (!value) return "other";
    if (ASSET_ICONS[value]) return value;
    if (ALIASES[value]) return ALIASES[value];
    return suggestIconFromName(value);
}

export const iconLabel = (value) => ASSET_ICONS[iconKey(value)].label;
export const iconColor = (value) => ICON_FAMILIES[ASSET_ICONS[iconKey(value)].family].color;
