/**
 * The New Backup dialog's choices: the assets from GET /api/backups/devices, each with the device
 * family detected for it, and the device type that follows the chosen asset.
 */
import { t } from "../../i18n";
import { FAMILY_LABELS } from "./restoreConstants.js";

export const BACKUP_FAMILIES = Object.keys(FAMILY_LABELS);

/** One asset's line in the list: "fw-dc (172.16.120.1) · FortiGate", or why it cannot be chosen. */
export function deviceLabel(device) {
    const ip = device.ip_address ? ` (${device.ip_address})` : ` - ${t("no IP address")}`;
    const family = device.family ? ` · ${FAMILY_LABELS[device.family] || device.family}` : "";
    return `${device.asset_name}${ip}${family}`;
}

/** The device type once `device` is chosen: the family detected for it, or none to choose. */
export function typeFor(device) {
    return device && BACKUP_FAMILIES.includes(device.family) ? device.family : "";
}

/** What the dialog says under the device type. */
export function typeHint(device, chosen) {
    if (!device) return "";
    if (!device.family) return t("The asset's type, vendor and system do not tell which device it is; choose it.");
    if (chosen && chosen !== device.family) {
        return t("Detected as {{detected}}; the backup is taken as {{chosen}}.", {
            detected: FAMILY_LABELS[device.family], chosen: FAMILY_LABELS[chosen] || chosen,
        });
    }
    return t("Detected from the asset: {{family}}", { family: FAMILY_LABELS[device.family] });
}
