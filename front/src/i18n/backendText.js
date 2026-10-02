import { t, n, currentLanguage } from "./index";

/*
 * Text that the API sends in English: alert titles and details, the
 * notification-rule catalogue, architecture-rule findings, design-template
 * labels and stored enum values (severity, status, ...).
 *
 * Messages that leave NGCorion (email, SMS, syslog, webhooks) stay English;
 * only what the UI shows is translated, here, at display time. Anything not
 * listed below - user-entered names, device output - is shown unchanged.
 *
 * msg() only marks a string for the extractor (npm run i18n:extract).
 */
const msg = (s) => s;

// ── Sentences with values: "{name}" placeholders, matched as a whole ────────
const TEMPLATES = [
    // alert titles
    msg("Vulnerability with CVSS {{score}} or higher"),
    msg("No backup for {{days}} days"),
    // alert details
    msg("No answer to SNMP for {{polls}} polls in a row (about {{minutes}} min) - {{error}}"),
    msg("No answer to SNMP for {{polls}} polls in a row (about {{minutes}} min)"),
    msg("{{name}} is down while enabled ({{alias}})"),
    msg("{{name}} is down while enabled"),
    msg("{{name}} at {{value}}% (in) on average over {{minutes}} min"),
    msg("{{name}} at {{value}}% (out) on average over {{minutes}} min"),
    msg("Last update {{date}} - {{age}} days ago. Findings may miss new vulnerabilities."),
    msg("{{before}}% -> {{after}}% since the audit of {{date}}"),
    msg("{{total}} device - oldest {{days}} days, {{never}} never backed up"),
    msg("{{total}} devices - oldest {{days}} days, {{never}} never backed up"),
    msg("{{total}} device - oldest {{days}} days"),
    msg("{{total}} devices - oldest {{days}} days"),
    msg("{{total}} device - {{never}} never backed up"),
    msg("{{total}} devices - {{never}} never backed up"),
    msg("{{total}} device"),
    msg("{{total}} devices"),
    msg("Running on the last validated license. {{message}}"),
    msg("{{task}} is not running in any worker"),
    msg("{{free}} GB free of {{total}} GB ({{path}})"),
    msg("{{ids}} and {{more}} more ({{product}})"),
    msg("{{ids}} and {{more}} more"),
    // rule catalogue summaries (values already filled in by the API)
    msg("No SNMP answer for {{polls}} polls in a row"),
    msg("Above {{percent}}% for {{minutes}} minutes"),
    msg("A finding with CVSS {{cvss}} or higher"),
    msg("No successful update for {{days}} days"),
    msg("An asset falls {{points}} points or more below its previous audit"),
    msg("Devices with no backup for {{days}} days"),
    msg("Scheduler, NOC poller or CVE update not running for {{minutes}} minutes"),
    msg("Less than {{gb}} GB free"),
    msg("{{module}} rule"),
    msg("Webhook · {{name}}"),
    msg("user #{{id}}"),
    // remediation alerts and rules
    msg("{{ref}} - due {{date}}"),
    msg("{{ref}} - until {{date}}"),
    msg("{{ref}} - ends {{date}}"),
    msg("A finding is not fixed {{days}} days after its deadline"),
    msg("An accepted risk ends within {{days}} days"),
    msg("This finding can be accepted for at most {{days}} days"),
];

// ── Fixed sentences: translated by exact match ────────────────────────────
msg("Device unreachable");
msg("Interface down");
msg("Interface utilization high");
msg("Exploited vulnerability on an asset");
msg("Critical vulnerability");
msg("CVE database outdated");
msg("Scheduled job failed");
msg("Scheduled audit failed");
msg("Scheduled discovery failed");
msg("Compliance dropped");
msg("Restore failed or reverted");
msg("Restore reverted automatically");
msg("Restore failed");
msg("Device without a recent backup");
msg("License problem");
msg("License server unreachable");
msg("License is not valid");
msg("Background task stopped");
msg("Disk space low");
msg("Remediation");
msg("Remediation overdue");
msg("Risk acceptance waiting for approval");
msg("Risk acceptance ending soon");
msg("Risk acceptance requested");
msg("Risk acceptance ending");
msg("A risk acceptance is waiting for approval");
msg("Days after the deadline");
msg("Days before the end");
// remediation API errors
msg("That user does not exist");
msg("This finding is closed; its status follows its source or its risk acceptance");
msg("A finding is resolved by the next audit or CVE check, not by hand");
msg("This finding is already resolved");
msg("A justification is required");
msg("The end date must be in the future");
msg("A risk acceptance for this is already pending or active");
msg("Only administrators and managers can decide on a risk acceptance");
msg("You cannot decide on your own request");
msg("Only an administrator can accept a critical or known-exploited finding");
msg("This request has already been decided");
msg("The requested end date has already passed; ask for a new request");
msg("Only a pending or active risk acceptance can be withdrawn");
msg("Only the requester, an administrator or a manager can withdraw this");
msg("Only the requester can cancel a pending request; reject it instead");
msg("Finding not found");
msg("Risk acceptance not found");
msg("An enabled interface goes down");
msg("A finding in CISA KEV appears on an asset");
msg("A scheduled audit or discovery could not run or finish");
msg("A restore ends failed or is reverted automatically");
msg("The license is not valid, or its server cannot be reached");
msg("Polls in a row");
msg("Only interfaces used by a Topology link (1 = yes, 0 = every port)");
msg("Only interfaces used by a Topology link");
msg("Utilization");
msg("For");
msg("CVSS at least");
msg("Days without update");
msg("Drop of at least");
msg("Days without backup");
msg("Not running for");
msg("Free space below");
msg("polls");
msg("minutes");
msg("days");
msg("points");
msg("Audit & Hardening");
msg("Backup & Restore");
msg("System");
msg("Admins");
msg("Managers");
msg("Users");
msg("Guests");
msg("the person behind it");
msg("Nobody - in-app only");
msg("Job scheduler");
msg("NOC poller");
msg("NOC metrics rollup");
msg("CVE automatic update");
msg("No license is activated on this machine. Activate a license key via POST /api/license/activate first.");
// architecture rules (app/modules/architecture_validation/rules)
msg("Asset has no IP address");
msg("Set the asset's IP address so audits, hardening and topology can target it.");
msg("Asset has no owner assigned");
msg("Assign an owner in Asset Management so there is a clear point of contact.");
msg("Confidentiality level not classified");
msg("Classify the asset's confidentiality level to drive risk scoring correctly.");
msg("Asset has no topology links");
msg("Add this asset's cabling in Topology so it is represented in the network diagram.");
msg("Asset has no redundant link");
msg("A single link is a single point of failure - add a redundant path in Topology.");
msg("Critical asset lacks redundancy");
msg("This asset is marked critical/high-risk but has no redundant link - prioritize adding one.");
msg("Critical asset has no configuration backup");
msg("Take a configuration backup for this asset (Configuration Backup) before its next change.");
msg("Asset has never been audited");
msg("Run a security audit for this asset to establish a compliance baseline.");
msg("Asset audit is stale");
msg("Re-run the audit - the last result is more than 90 days old.");
msg("High-risk asset is active without a recent audit");
msg("This asset is high risk and active - audit it within 30 days.");
msg("Last audit failed");
msg("The most recent audit run failed to complete - investigate and re-run it.");
// design template (app/modules/design/templates.py)
msg("Small (< 50 devices, single site)");
msg("Medium (50-200 devices)");
msg("Large (200+ devices, multiple wings/floors)");
msg("Internet");
msg("Internet Edge Router");
msg("Perimeter Firewall");
msg("DMZ Load Balancer");
msg("DMZ Web Server");
msg("Core Switch 1");
msg("Core Switch 2");
msg("Distribution Switch 1");
msg("Distribution Switch 2");
msg("Data Center Firewall");
msg("Data Center Switch");
msg("Data Center Server");
msg("Wireless AP");
msg("Access Switch {{n}}");

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const COMPILED = TEMPLATES.map((key) => {
    const names = [];
    const source = key.split(/(\{\{\w+\}\})/).map((part) => {
        const m = /^\{\{(\w+)\}\}$/.exec(part);
        if (!m) return escape(part);
        names.push(m[1]);
        return "(.+?)";
    }).join("");
    return { key, names, re: new RegExp(`^${source}$`, "s") };
});
COMPILED.push({ key: "Access Switch {{n}}", names: ["n"], re: /^Access Switch (\d+)$/ });

/** Translate one English sentence from the API; unknown text comes back unchanged. */
export function tb(text) {
    if (typeof text !== "string" || !text) return text;
    const exact = t(text);
    if (exact !== text) return exact;
    for (const { key, names, re } of COMPILED) {
        const m = re.exec(text);
        if (!m) continue;
        const values = Object.fromEntries(names.map((name, i) => [name, n(tb(m[i + 1]))]));
        return t(key, values);
    }
    return text;
}

/** Comma-joined API lists such as "Admins, r.karimi, the person behind it". */
export const tbList = (text) => (typeof text === "string"
    ? text.split(", ").map(tb).join(currentLanguage() === "fa" ? "، " : ", ")
    : text);

// ── Stored enum values ─────────────────────────────────────────────────────
const VALUES = {
    critical: t("Critical"),
    very_high: t("Very high"),
    high: t("High"),
    medium: t("Medium"),
    low: t("Low"),
    info: t("Info"),
    informational: t("Informational"),
    warning: t("Warning"),
    public: t("Public"),
    internal: t("Internal"),
    confidential: t("Confidential"),
    restricted: t("Restricted"),
    active: t("Active"),
    inactive: t("Inactive"),
    standby: t("Standby"),
    decommissioned: t("Decommissioned"),
    unknown: t("Unknown"),
    admin: t("admin"),
    manager: t("manager"),
    user: t("user"),
    guest: t("guest"),
    well_known: t("Well-known ports"),
    well_known_ports: t("Well-known ports"),
    custom_ports: t("Custom ports"),
    all_ports: t("All ports"),
    custom: t("Custom ports"),
    redundancy: t("Redundancy"),
    exposure: t("Exposure"),
    best_practice: t("Best practice"),
    inventory: t("Inventory"),
    topology: t("Topology"),
    resilience: t("Resilience"),
    compliance: t("Compliance"),
    network: t("Network"),
    server: t("Server"),
};

/** Label for a stored enum value ("very_high" -> "Very high"); other values unchanged. */
export function tv(value) {
    if (value === null || value === undefined || value === "") return value;
    return VALUES[String(value).toLowerCase()] ?? value;
}
