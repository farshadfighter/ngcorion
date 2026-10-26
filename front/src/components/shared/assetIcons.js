import { t } from "../../i18n";
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
    network: { label: t("Network"), color: "#1d4ed8" },
    security: { label: t("Security"), color: "#c2410c" },
    compute: { label: t("Compute"), color: "#334155" },
    platforms: { label: t("Containers & virtualisation"), color: "#0e7490" },
    services: { label: t("Services"), color: "#6d28d9" },
    storage: { label: t("Storage"), color: "#a16207" },
    endpoints: { label: t("Endpoints"), color: "#15803d" },
    facilities: { label: t("Cameras, power & OT"), color: "#4d7c0f" },
    external: { label: t("External"), color: "#0f766e" },
    identity: { label: t("Directory & network services"), color: "#be185d" },
    other: { label: t("Other"), color: "#6b7280" },
};

// Glyphs are drawn on a 24x24 grid as a single stroked path.
export const ASSET_ICONS = {
    router: {
        label: t("Router"), family: "network",
        d: "M16 12a4 4 0 1 1-8 0a4 4 0 1 1 8 0M9.2 9.2 5.5 5.5M5.5 8.3V5.5h2.8M14.8 14.8l3.7 3.7M18.5 15.7v2.8h-2.8M18.5 5.5l-3.7 3.7M14.8 6.4v2.8h2.8M5.5 18.5l3.7-3.7M9.2 17.6v-2.8H6.4",
    },
    switch: { label: t("Switch"), family: "network", d: "M5 9h13M15 6l3 3-3 3M19 15H6M9 12l-3 3 3 3" },
    wireless: {
        label: t("Wireless AP"), family: "network",
        d: "M12 20v-5.5M8.6 11.1a4.8 4.8 0 0 1 6.8 0M6 8.4a8.5 8.5 0 0 1 12 0M12 14.2h.01",
    },
    load_balancer: {
        label: t("Load balancer"), family: "network",
        d: "M12 4v6M12 10l-6 4.5V19M12 10v9M12 10l6 4.5V19M4 17l2 2 2-2M10 17l2 2 2-2M16 17l2 2 2-2",
    },
    firewall: {
        label: t("Firewall"), family: "security",
        d: "M4 6h16v12H4zM4 10h16M4 14h16M9 6v4M15 6v4M12 10v4M7 14v4M17 14v4",
    },
    waf: {
        label: t("Web application firewall"), family: "security",
        d: "M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6zM8 11h8M12 7.5c1.3 1.1 2 2.3 2 3.5s-.7 2.4-2 3.5M12 7.5c-1.3 1.1-2 2.3-2 3.5s.7 2.4 2 3.5",
    },
    ips: {
        label: t("IPS / IDS"), family: "security",
        d: "M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6zM7.5 12s1.8-3 4.5-3 4.5 3 4.5 3-1.8 3-4.5 3-4.5-3-4.5-3M12 12h.01",
    },
    vpn: {
        label: t("VPN gateway"), family: "security",
        d: "M7 11h10v9H7zM9.5 11V8.2a2.5 2.5 0 0 1 5 0V11M12 14.5v2M2.5 15.5H7M17 15.5h4.5",
    },
    server: {
        label: t("Physical server"), family: "compute",
        d: "M6 3.5h12v17H6zM6 9.2h12M6 14.8h12M9 6.4h.01M9 12h.01M9 17.7h.01M12.5 6.4h3M12.5 12h3M12.5 17.7h3",
    },
    hypervisor: { label: t("Virtual host"), family: "platforms", d: "M9 4h11v11H9zM6.5 6.5v11h11M4 9v11h11" },
    container: {
        label: t("Container host"), family: "platforms",
        d: "M3.5 11h17v6.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2zM5.5 7h4v4h-4zM9.5 7h4v4h-4zM9.5 3h4v4h-4zM13.5 7h4v4h-4z",
    },
    cluster: {
        label: t("Kubernetes cluster"), family: "platforms",
        d: "M12 3l7.5 3.6 1.8 8-5.2 6.4H7.9l-5.2-6.4 1.8-8zM14.5 12a2.5 2.5 0 1 1-5 0a2.5 2.5 0 1 1 5 0M12 6v3.5M12 14.5V18M6.8 9.3l2.9 1.6M14.3 13.1l2.9 1.6M17.2 9.3l-2.9 1.6M9.7 13.1l-2.9 1.6",
    },
    linux: { label: t("Linux server"), family: "compute", d: "M3.5 5h17v14h-17zM7 10l3 2.5L7 15M12.5 15h4.5" },
    windows: {
        label: t("Windows server"), family: "compute",
        d: "M3.5 5h17v14h-17zM3.5 9h17M6.5 7h.01M9 7h.01M7 12.5h10M7 15.5h6",
    },
    web: {
        label: t("Web server"), family: "services",
        d: "M20 12a8 8 0 1 1-16 0a8 8 0 1 1 16 0M4 12h16M12 4c2.4 2.4 3.4 5 3.4 8s-1 5.6-3.4 8M12 4C9.6 6.4 8.6 9 8.6 12s1 5.6 3.4 8",
    },
    database: {
        label: t("Database"), family: "services",
        d: "M5.5 6.5c0-1.4 2.9-2.5 6.5-2.5s6.5 1.1 6.5 2.5S15.6 9 12 9 5.5 7.9 5.5 6.5zM5.5 6.5v11c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5v-11M5.5 12c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5",
    },
    storage: {
        label: t("Storage"), family: "storage",
        d: "M3.5 6h17v5h-17zM3.5 13h17v5h-17zM16.5 8.5h.01M16.5 15.5h.01M6.5 8.5h6M6.5 15.5h6",
    },
    workstation: { label: t("PC / workstation"), family: "endpoints", d: "M3.5 4.5h17v11h-17zM9 20h6M12 15.5V20" },
    laptop: { label: t("Laptop"), family: "endpoints", d: "M5 5.5h14v10H5zM2.5 19h19l-1.5-3.5H4z" },
    ip_phone: {
        label: t("IP phone"), family: "endpoints",
        d: "M3.5 8.5h17v11h-17zM5.5 8.5V5h4v3.5M12 11.5h6V14h-6zM12 17h.01M15 17h.01M18 17h.01M7.5 11v6",
    },
    printer: {
        label: t("Printer"), family: "endpoints",
        d: "M7 8.5V3.5h10v5M7 17H5a1.5 1.5 0 0 1-1.5-1.5V10A1.5 1.5 0 0 1 5 8.5h14a1.5 1.5 0 0 1 1.5 1.5v5.5A1.5 1.5 0 0 1 19 17h-2M7 13.5h10v7H7zM16.5 11h.01",
    },
    iot: {
        label: t("IoT device"), family: "endpoints",
        d: "M8 8h8v8H8zM10.5 4v4M13.5 4v4M10.5 16v4M13.5 16v4M4 10.5h4M4 13.5h4M16 10.5h4M16 13.5h4",
    },
    camera: {
        label: t("IP camera"), family: "facilities",
        d: "M3.5 6.5H17l2.5 3-2.5 3H3.5zM14.5 9.5h.01M8.5 12.5V17M5 20h7M8.5 17v3",
    },
    nvr: {
        label: t("Video recorder (NVR)"), family: "facilities",
        d: "M3 7.5h18v9H3zM7 12a1.5 1.5 0 1 1-3 0a1.5 1.5 0 1 1 3 0M10 10.5h7.5M10 13.5h5M5.5 16.5v2M18.5 16.5v2",
    },
    ups: {
        label: t("UPS"), family: "facilities",
        d: "M4 6h16v13H4zM9 3.5V6M15 3.5V6M12.8 8.5l-2.8 4h4l-2.8 4",
    },
    plc: {
        label: t("PLC / industrial"), family: "facilities",
        d: "M4 4h16v16H4zM4 8.5h16M7.5 4v4.5M11 4v4.5M14.5 4v4.5M7 12h4v5H7zM14 12.5h3M14 15h3M14 17.5h3",
    },
    directory: {
        label: t("Directory (AD)"), family: "identity",
        d: "M10 3h4v4h-4zM3.5 17h4v4h-4zM10 17h4v4h-4zM16.5 17h4v4h-4zM12 7v10M5.5 17v-3h13v3",
    },
    dns: { label: t("DNS server"), family: "identity", d: "M12 3v18M12 5.5h6.5l2 2.5-2 2.5H12M12 12.5H5.5l-2 2.5 2 2.5H12" },
    dhcp: {
        label: t("DHCP server"), family: "identity",
        d: "M3.5 12V5a1.5 1.5 0 0 1 1.5-1.5h7l9 9-8.5 8.5zM7.5 7.5h.01M10 13l3-3M12 15l3-3",
    },
    internet: {
        label: t("Internet"), family: "external",
        d: "M7 18.5a4.5 4.5 0 0 1-.4-9 6 6 0 0 1 11.3 1.3A3.9 3.9 0 0 1 17.5 18.5z",
    },
    mpls: {
        label: t("MPLS"), family: "external",
        d: "M7 18.5a4.5 4.5 0 0 1-.4-9 6 6 0 0 1 11.3 1.3A3.9 3.9 0 0 1 17.5 18.5zM8.5 14.5h6.5M13 12.5l2 2-2 2",
    },
    wan: {
        label: t("WAN / leased line"), family: "external",
        d: "M2.5 8.5h5v7h-5zM16.5 8.5h5v7h-5zM7.5 12h9M10 10.5l-1.5 1.5 1.5 1.5M14 10.5l1.5 1.5-1.5 1.5",
    },
    sdwan: {
        label: t("SD-WAN"), family: "external",
        d: "M2.5 9h4v6h-4zM17.5 9h4v6h-4zM6.5 12h2M15.5 12h2M10.2 14.5a1.9 1.9 0 0 1 .1-3.8 2.6 2.6 0 0 1 4.9.6 1.6 1.6 0 0 1-.4 3.2z",
    },
    lte: {
        label: t("LTE / 4G backup"), family: "external",
        d: "M12 21V11M9 21l3-10 3 10M8.6 7.6a4.8 4.8 0 0 1 6.8 0M6.2 5.2a8.2 8.2 0 0 1 11.6 0M12 9.6h.01",
    },
    public_cloud: {
        label: t("Public cloud"), family: "external",
        d: "M7 18.5a4.5 4.5 0 0 1-.4-9 6 6 0 0 1 11.3 1.3A3.9 3.9 0 0 1 17.5 18.5zM9.5 13h5M9.5 15.5h5M10.5 13v2.5M13.5 13v2.5",
    },
    partner: {
        label: t("Partner network"), family: "external",
        d: "M4.5 12a3.8 3.8 0 1 0 7.6 0a3.8 3.8 0 1 0-7.6 0M11.9 12a3.8 3.8 0 1 0 7.6 0a3.8 3.8 0 1 0-7.6 0",
    },
    other: {
        label: t("Other"), family: "other",
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
    [/\bwaf\b|web ?application ?firewall|fortiweb|imperva|modsecurity/i, "waf"],
    [/\bips\b|\bids\b|intrusion|snort|suricata/i, "ips"],
    [/mpls ?vpn|\bl[23] ?vpn\b|\bvpls\b/i, "mpls"],
    [/\bvpn\b|anyconnect|openvpn|wireguard/i, "vpn"],
    [/firewall|fortigate|palo ?alto|\basa\b|\butm\b|check ?point|sophos/i, "firewall"],
    [/load ?balanc|\bf5\b|big-?ip|haproxy|\badc\b/i, "load_balancer"],
    [/router|gateway|\bisr\b|\basr\b/i, "router"],
    [/wireless|wi-?fi|access ?point|\bap\b|\bwlc\b/i, "wireless"],
    [/switch|catalyst|nexus/i, "switch"],
    [/kubernetes|\bk8s\b|openshift|rancher/i, "cluster"],
    [/docker|podman|container/i, "container"],
    [/hypervisor|esxi|vmware|hyper-?v|proxmox|virtual ?host|vcenter|\bxen/i, "hypervisor"],
    [/database|\bdb\b|mongo|mssql|sql ?server|mysql|postgres|oracle|mariadb|redis/i, "database"],
    [/\bweb|apache|nginx|\biis\b|tomcat/i, "web"],
    [/storage|\bnas\b|\bsan\b|netapp|synology/i, "storage"],
    [/active ?directory|domain ?controller|\bldap\b/i, "directory"],
    [/\bdns\b/i, "dns"],
    [/\bdhcp\b/i, "dhcp"],
    [/windows/i, "windows"],
    [/linux|ubuntu|debian|centos|rhel|red ?hat|rocky|alma|suse|fedora/i, "linux"],
    [/laptop|notebook|macbook|thinkpad/i, "laptop"],
    [/workstation|desktop|\bpc\b|endpoint/i, "workstation"],
    [/ip ?phone|voip|\bsip\b|desk ?phone|telephone/i, "ip_phone"],
    [/printer|\bmfp\b|\bmfd\b|multi-?function|copier|plotter|laserjet/i, "printer"],
    [/\bnvr\b|\bdvr\b|video ?recorder/i, "nvr"],
    [/camera|cctv|\bip ?cam/i, "camera"],
    [/\bups\b|uninterruptible/i, "ups"],
    [/\bplc\b|scada|\bhmi\b|\brtu\b|industrial|operational technology/i, "plc"],
    [/\biot\b|sensor/i, "iot"],
    [/\bmpls\b/i, "mpls"],
    [/sd-?wan/i, "sdwan"],
    [/\blte\b|\b[45]g\b|cellular|mobile ?data/i, "lte"],
    [/\baws\b|azure|\bgcp\b|google cloud|public ?cloud|\biaas\b/i, "public_cloud"],
    [/partner|extranet|third.party network/i, "partner"],
    [/\bwan\b|leased ?line|metro ?ethernet|point.to.point/i, "wan"],
    [/internet|\bisp\b|cloud/i, "internet"],
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
