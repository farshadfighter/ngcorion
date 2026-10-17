/**
 * Formatting shared by the NOC device-health views (host page, host list): percentages and
 * temperatures in the UI's digits, the level a value is at, sizes and durations.
 */
import { n, t } from "../../i18n";

// Colour bands for a usage bar; the alerts have their own thresholds (Notifications rules).
export const level = (value, warn = 75, bad = 90) => (value == null ? "none" : value >= bad ? "bad" : value >= warn ? "warn" : "ok");

export const pct = (value) => (value == null ? "—" : n(`${Math.round(value)}%`));

export const celsius = (value) => (value == null ? "—" : t("{{value}} °C", { value: n(Math.round(value)) }));

const UNITS = [
    (value) => t("{{value}} B", { value }), (value) => t("{{value}} KB", { value }),
    (value) => t("{{value}} MB", { value }), (value) => t("{{value}} GB", { value }),
    (value) => t("{{value}} TB", { value }),
];

export function bytes(value) {
    if (value == null) return "—";
    let v = value;
    let i = 0;
    while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i += 1; }
    return UNITS[i](n(Number(v.toFixed(v >= 100 || i === 0 ? 0 : 1))));
}

export function duration(seconds) {
    if (seconds == null) return "—";
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return t("{{days}} d {{hours}} h", { days: n(days), hours: n(hours) });
    if (hours > 0) return t("{{hours}} h {{minutes}} min", { hours: n(hours), minutes: n(minutes) });
    return t("{{minutes}} min", { minutes: n(minutes) });
}

export const SOURCE_LABELS = {
    "host-resources": "HOST-RESOURCES-MIB",
    ucd: "UCD-SNMP-MIB (net-snmp)",
    cisco: "Cisco (PROCESS / MEMORY-POOL / ENVMON)",
    fortigate: "FortiGate (FORTINET-FORTIGATE-MIB)",
};
