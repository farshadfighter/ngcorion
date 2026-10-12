import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";

/*
 * Labels shared by the asset group, group audit and credential profile screens
 * (backend: app/modules/asset_groups).
 */

export const TECHS = {
    cisco: "Cisco IOS",
    fortinet: "FortiGate",
    linux: "Linux",
    apache: "Apache",
    mongodb: "MongoDB",
    mssql: "SQL Server",
    windows: "Windows Server",
    active_directory: "Active Directory",
    dns_server: "Windows DNS Server",
    dhcp_server: "Windows DHCP Server",
    iis: "IIS 10",
    docker: "Docker",
    kubernetes: "Kubernetes",
    mysql: "MySQL 8",
    esxi: "VMware ESXi",
    nginx: "NGINX",
    sophos: "Sophos Firewall",
};

export const KINDS = {
    ssh: t("SSH"),
    winrm: t("WinRM (Windows)"),
    mssql: t("SQL Server login"),
    sophos_api: t("Sophos API"),
};

export const FIELDS = {
    type: { label: t("Asset type"), ops: ["eq", "neq"], input: "type" },
    zone: { label: t("Zone"), ops: ["eq", "neq"], input: "zone" },
    owner: { label: t("Owner"), ops: ["eq", "neq"], input: "owner" },
    location: { label: t("Location"), ops: ["eq", "neq"], input: "location" },
    status: { label: t("Status"), ops: ["eq", "neq"], input: "status" },
    os: { label: t("Operating system"), ops: ["contains", "eq"], input: "text" },
    vendor: { label: t("Manufacturer"), ops: ["contains", "eq"], input: "text" },
    name: { label: t("Name"), ops: ["contains"], input: "text" },
    tag: { label: t("Tag"), ops: ["has", "not_has"], input: "tag" },
    ip: { label: t("IP range"), ops: ["in", "not_in"], input: "cidr" },
};

export const OPS = {
    eq: t("is"),
    neq: t("is not"),
    contains: t("contains"),
    has: t("has"),
    not_has: t("does not have"),
    in: t("is in"),
    not_in: t("is not in"),
};

export const STATUSES = {
    active: t("Active"),
    standby: t("Standby"),
    decommissioned: t("Decommissioned"),
    unknown: t("Unknown"),
    inactive: t("Inactive"),
};

export const RUN_STATUS = {
    queued: { label: t("Waiting"), cls: "bkm-pill-muted" },
    running: { label: t("Running"), cls: "bkm-pill-run" },
    stopping: { label: t("Stopping"), cls: "bkm-pill-amber" },
    stopped: { label: t("Stopped"), cls: "bkm-pill-muted" },
    done: { label: t("Finished"), cls: "bkm-pill-ok" },
};

export const ITEM_STATUS = {
    queued: { label: t("Waiting"), cls: "bkm-pill-muted" },
    running: { label: t("Running"), cls: "bkm-pill-run" },
    done: { label: t("Done"), cls: "bkm-pill-ok" },
    failed: { label: t("Failed"), cls: "bkm-pill-bad" },
    skipped: { label: t("Skipped"), cls: "bkm-pill-amber" },
    cancelled: { label: t("Cancelled"), cls: "bkm-pill-muted" },
};

export const REASONS = {
    auth: t("Sign-in refused"),
    unreachable: t("Unreachable"),
    license: t("Not covered by the license"),
    no_address: t("No IP address"),
    error: t("Error"),
    interrupted: t("Interrupted by a restart"),
};

export const errorText = (err, fallback) => {
    const detail = err?.response?.data?.detail;
    if (typeof detail === "string") return tb(detail);
    if (Array.isArray(detail)) return detail.map((d) => tb(String(d.msg || "").replace(/^Value error, /, ""))).join(" ");
    return fallback;
};

/** A condition as a sentence: "Asset type is Linux Server". `options` names the ids it refers to. */
export const ruleText = (rule, options) => {
    const f = FIELDS[rule.field];
    if (!f) return "";
    const choices = options?.[f.input];
    const value = Array.isArray(choices)
        ? (choices.find((c) => String(c.value) === String(rule.value))?.label ?? `#${rule.value}`)
        : rule.value;
    return `${f.label} ${OPS[rule.op] || rule.op} ${value}`;
};
