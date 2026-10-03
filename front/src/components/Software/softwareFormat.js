import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";

// Shared labels for the software inventory pages.

/** Where an installed item came from (SoftwareItem.source). */
export const SOURCE = {
    distro: { label: t("Distribution repository"), short: t("Distribution"), cls: "sw-src-distro" },
    third_party: { label: t("Third-party repository"), short: t("Third-party"), cls: "sw-src-third" },
    manual: { label: t("Installed manually"), short: t("Manual"), cls: "sw-src-manual" },
    windows: { label: t("Windows program"), short: t("Windows"), cls: "sw-src-win" },
    service: { label: t("Read by the service's audit"), short: t("Service"), cls: "sw-src-audit" },
    firmware: { label: t("Device firmware"), short: t("Firmware"), cls: "sw-src-audit" },
};
export const SOURCE_ORDER = ["distro", "third_party", "manual", "windows", "service", "firmware"];

export const COLLECTOR = {
    linux: t("Linux audit"),
    windows: t("Windows audit"),
    apache: t("Apache audit"),
    mongodb: t("MongoDB audit"),
    mssql: t("SQL Server audit"),
    cisco: t("Cisco audit"),
    fortinet: t("Fortinet audit"),
};

export const KIND = {
    package: t("Package"),
    program: t("Program"),
    hotfix: t("Update"),
    os: t("Operating system"),
    service: t("Service"),
    firmware: t("Firmware"),
};

export const SEVERITY = {
    critical: { label: t("Critical"), cls: "sw-sev-c" },
    high: { label: t("High"), cls: "sw-sev-h" },
    medium: { label: t("Medium"), cls: "sw-sev-m" },
    low: { label: t("Low"), cls: "sw-sev-l" },
};

export const CHANGE = {
    added: { label: t("Added"), cls: "sw-tag-add" },
    updated: { label: t("Updated"), cls: "sw-tag-up" },
    removed: { label: t("Removed"), cls: "sw-tag-rm" },
};

/** Linux or Windows, for the collect-now form. */
export const platformOf = (asset) => (/windows/i.test(`${asset?.os_name || ""} ${asset?.inferred_device_type || ""} ${asset?.resolved_icon || ""}`) ? "windows" : "linux");

export const count = (v) => (v == null ? "—" : n(v));

export const errorText = (e, fallback) => {
    const detail = e?.response?.data?.detail;
    if (typeof detail === "string") return tb(detail);
    if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
    return fallback;
};

/** Save a blob the API sent as a file. */
export function saveBlob(data, name) {
    const url = window.URL.createObjectURL(new Blob([data]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", name);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
}
