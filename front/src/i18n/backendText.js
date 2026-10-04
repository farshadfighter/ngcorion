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
    // NGCorion self-backup (app/modules/sysbackup)
    msg("No successful backup in the last {{hours}} hours"),
    msg("No successful backup for {{hours}} hours"),
    msg("Cannot reach {{target}} ({{error}})"),
    msg("Cannot write to the share: {{error}}"),
    msg("SFTP connection failed: {{error}}"),
    msg("Windows share connection failed: {{error}}"),
    msg("Writing to the share failed: {{error}}"),
    msg("Keep between {{lo}} and {{hi}}"),
    msg("The copy on the destination has {{size}} bytes instead of {{expected}}"),
    msg("The passphrase must be at least {{min}} characters"),
    msg("This is not a usable NGCorion backup: {{reason}}"),
    msg("The backup cannot be read: {{reason}}"),
    msg("The backup was restored, but a final step failed: {{reason}}"),
    msg("file is damaged (chunk {{n}} failed its check)"),
    msg("row counts differ: {{tables}}"),
    msg("tables missing from the backup: {{tables}}"),
    msg("the backup has a table this version does not know: {{name}}"),
    msg("the backup is inconsistent: {{name}}"),
    msg("{{name}} does not match its recorded checksum"),
    msg("{{name}} is not in the manifest"),
    msg("Uploaded: {{name}}"),
    msg("Before restoring {{when}}"),
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
    // CVE database jobs (app/modules/cve/feeds.py)
    msg("NVD is not reachable: {{error}}"),
    msg("CISA KEV is not reachable: {{error}}"),
    msg("EPSS is not reachable: {{error}}"),
    // distribution advisories (app/modules/advisories)
    msg("OSV.dev is not reachable: {{error}}"),
    msg("OSV answered HTTP {{code}} for {{ecosystem}}"),
    msg("OSV answered HTTP {{code}} for the change list of {{ecosystem}}"),
    msg("The file is larger than the {{num}} MB limit."),
    msg("Unknown release: {{release}}"),
    // reports
    msg("Not an email address: {{email}}"),
    msg("Building the report failed: {{error}}"),
    msg("SMTP error: {{error}}"),
    msg("{{name}} - {{error}}"),
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
// reports: catalog (app/modules/reports/templates.py)
msg("Management");
msg("Audit and hardening");
msg("Vulnerability, risk and remediation");
msg("Assets and infrastructure");
msg("System");
msg("Security executive summary");
msg("Risk score and its trend, compliance, critical vulnerabilities, fixing on time and exceptions; with key points and a comparison with the previous period.");
msg("Summary and key points");
msg("Figures and sentences drawn from the data");
msg("Risk score trend");
msg("Weekly, with the riskiest assets");
msg("CIS compliance");
msg("By asset");
msg("Vulnerabilities");
msg("Critical and known exploited");
msg("Remediation and deadlines");
msg("Findings past their deadline");
msg("Accepted risks");
msg("Exceptions in force");
msg("Backups");
msg("Devices without a recent backup");
msg("Appendix: every open finding");
msg("As a separate Excel file");
msg("Pass rate of each asset and each part of the benchmark, failed checks with evidence, and the change since the previous audit.");
msg("Overview");
msg("Compliance by asset");
msg("Most common failures");
msg("Failed checks");
msg("Every failed check of each asset");
msg("Not audited in the period");
msg("Include the evidence of each failed check");
msg("Vulnerabilities (CVE)");
msg("Findings by asset and product, known exploited ones (KEV) and the chance of exploitation (EPSS).");
msg("Fix first");
msg("Known exploited, CVSS 9+ or EPSS 50%+");
msg("All findings");
msg("Severity");
msg("All");
msg("Medium and above");
msg("High and above");
msg("Critical only");
msg("Only known exploited (KEV)");
msg("Asset risk");
msg("Risk score of each asset, the factors behind it and its trend over the period.");
msg("Trend");
msg("Risk by asset");
msg("Risk factors");
msg("Remediation and accepted risks");
msg("Fixing on time, findings past their deadline by owner, and the list of exceptions with reason and approver.");
msg("By owner");
msg("Past the deadline");
msg("Open by source and severity");
msg("Fixed in the period");
msg("Every open finding");
msg("Sources");
msg("CVE");
msg("Audit");
msg("Architecture");
msg("Audit details");
msg("Hardening changes");
msg("What changed, on which device, by whom, with the backup taken before the change.");
msg("Assets and coverage");
msg("Backup and restore");
msg("How recent each device's backup is, restores and their result.");
msg("Availability (NOC)");
msg("Availability, outages and interface use.");
msg("Architecture validation");
msg("Architecture findings and the decision on each.");
msg("Alerts");
msg("Alerts in the period, time to acknowledge and resolve, noisiest sources.");
msg("User activity");
msg("Logins, failed logins and sensitive actions of each user.");
// reports: phase 2 catalog (app/modules/reports/templates2.py)
msg("The full result of one audit with the evidence of every check; for the auditor.");
msg("Summary");
msg("With evidence and how to fix");
msg("Errors and not applicable");
msg("Checks that need a look by hand");
msg("Passed checks");
msg("Change since the previous audit");
msg("Newly failing, newly passing");
msg("Which audit");
msg("Latest audit of each asset");
msg("One audit");
msg("Include why each check matters and how to fix it");
msg("Every change");
msg("Time, asset, check, user, result");
msg("Failed changes");
msg("With the error");
msg("Include the commands sent to the device");
msg("Which assets are audited, backed up, monitored and have a software list, and which are not.");
msg("Coverage");
msg("Assets with a gap");
msg("Only the assets that miss something");
msg("By asset type and location");
msg("Every asset");
msg("An audit counts as recent within");
msg("30 days");
msg("90 days");
msg("180 days");
msg("Restores");
msg("Who, why, result, automatic revert");
msg("Backups taken");
msg("By device and source");
msg("NGCorion's own backups");
msg("Administrators only");
msg("Availability by device");
msg("With a bar for every day");
msg("Outages");
msg("Start and duration");
msg("Busiest interfaces");
msg("Average and peak");
msg("Interfaces down");
msg("Enabled but down now");
msg("Availability target");
msg("99%");
msg("99.5%");
msg("99.9%");
msg("99.99%");
msg("Open findings");
msg("With the recommendation");
msg("Decisions");
msg("Accepted or ignored, with the reason");
msg("By rule");
msg("Noisiest sources");
msg("Still open");
msg("At the end of the period");
msg("Every alert");
msg("Modules");
msg("NOC");
msg("Software");
msg("Each user");
msg("Logins, last login, sensitive actions");
msg("Failed logins by address");
msg("Sensitive actions");
msg("Hardening, restores, deletions, permissions, settings");
msg("Unused accounts");
msg("No login in 90 days");
msg("Software inventory");
msg("Software outside the distribution repository, vulnerable products and new installations.");
msg("Vulnerable products");
msg("Affected versions and the fix");
msg("New software in the period");
msg("Installed manually or from a new repository");
msg("Outside the distribution repository");
msg("Several versions");
msg("Products with more than one version");
msg("Unidentified");
msg("Every installed package");
// distribution advisories: API errors
msg("The file holds no advisory of a supported distribution (Ubuntu, Debian, Red Hat, Rocky Linux, AlmaLinux). Download all.zip of the release from OSV.dev.");
msg("Not an OSV archive (not a ZIP file).");
msg("Not an OSV archive (not a valid ZIP file).");
msg("The OSV archive is larger than allowed.");
msg("An asset runs this release; it cannot be removed.");
msg("Wait for the running database job to finish.");
msg("Cancelled - the database was not changed.");
msg("Interrupted by a server restart. The database was not changed - run it again.");
// reports: API errors and alerts
msg("A schedule needs a period that moves with it, not fixed dates");
msg("A scheduled report could not be built or emailed");
msg("Add at least one recipient");
msg("Building was interrupted; build the report again");
msg("Choose PDF, Excel or both");
msg("Choose a day of the month between 1 and 28");
msg("Choose at least one item for the asset filter");
msg("Choose at least one section");
msg("Choose the day of the week");
msg("Choose the start and end of the period");
msg("Could not work out the next run");
msg("Enter the time as HH:MM");
msg("File too large (max 50 MB)");
msg("Give the schedule a name");
msg("Keep reports between 30 and 3650 days");
msg("None of the chosen sections can be built with your permissions");
msg("Only a report that has not started can be cancelled");
msg("Report not found");
msg("Reports");
msg("Schedule not found");
msg("Scheduled report failed");
msg("The logo must be a PNG or JPEG image");
msg("The logo must be smaller than 200 KB");
msg("The owner of this schedule no longer has an active account");
msg("The period ends before it starts");
msg("The period starts in the future");
msg("The person this report is built for no longer has an active account");
msg("This report has no such file");
msg("Unknown asset filter");
msg("Unknown classification");
msg("Unknown frequency");
msg("Unknown language");
msg("Unknown period");
msg("Unknown recipient");
msg("Unknown view");
msg("Wait for the report to finish, or cancel it");
msg("You already have 3 reports being built; wait for one to finish");
msg("You have no access to this report");
msg("Unknown report");
msg("This report is not available yet");
msg("The schedule could not run");
msg("Email is not configured - set SMTP in System Configuration");
msg("Choose the audit this report describes");
msg("A schedule describes the latest audit of each asset, not one fixed audit");
msg("The audit this report describes was not found or did not complete");
msg("Only an administrator can build this report");
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
// Software inventory: API errors, collection errors, alert catalogue (app/modules/software, alerts/events.py)
msg("New software outside known repositories");
msg("Software installed by hand or from a repository new to the asset");
msg("The asset has no IP address");
msg("The username or password was not accepted");
msg("Could not connect to the asset");
msg("Nothing could be collected");
msg("The package list could not be read");
msg("No installed package was found in the output");
msg("No installed program was found in the output");
msg("Mapping not found");
msg("Unknown product");
msg("Unknown choice");
msg("Enter the vendor and product the way NVD writes them, e.g. vendor:product");
// NGCorion self-backup: API errors, alert catalogue (app/modules/sysbackup, alerts/events.py)
msg("NGCorion backup failed");
msg("The last backup of NGCorion itself failed");
msg("No recent NGCorion backup");
msg("No backup for");
msg("hours");
msg("NGCorion backups are not set up");
msg("Set the backup passphrase so daily backups can run");
msg("Backup destination unreachable");
msg("A copy could not be sent to an SFTP server or Windows share");
msg("Backup restore test failed");
msg("The weekly test restore of a backup failed");
msg("A backup is already waiting to run");
msg("A backup or restore test is running; try again when it finishes");
msg("A restore is already running");
msg("Another backup, restore or restore test is running; try again when it finishes");
msg("Authentication failed");
msg("Authentication failed: check the username and password or key");
msg("Authentication failed: check the username, domain and password");
msg("Backup not found");
msg("Destination not found");
msg("Enter only the server name or address");
msg("Enter the passphrase this backup was made with");
msg("Enter the share name");
msg("Less than 256 MB free in the backup folder");
msg("Only a finished backup can be restored");
msg("Restore not found");
msg("Set the backup passphrase first");
msg("The backup file is missing");
msg("The backup has no file");
msg("The backup is not ready");
msg("The backup is still being written");
msg("The backup no longer exists");
msg("The current passphrase is not correct");
msg("The file is empty");
msg("The file is too large");
msg("The passphrase does not open this backup");
msg("The passphrase is too long");
msg("The private key could not be read (OpenSSH or PEM, without a passphrase)");
msg("The server presented a different host key than the one pinned. If the server was reinstalled, clear the pinned key and test again.");
msg("The stored password could not be opened; enter it again");
msg("This backup comes from a newer NGCorion version. Update this server first, then restore it.");
msg("Type RESTORE to confirm");
msg("Unknown backup content");
msg("Unknown weekday");
msg("Your password is not correct");
msg("The backup was interrupted");
msg("The restore was interrupted");
msg("The file is no longer in the backup folder");
msg("The backup passphrase is not set");
msg("archive ends in the middle of an entry");
msg("archive is damaged");
msg("entry is larger than expected");
msg("file is cut short");
msg("file is damaged");
msg("header is damaged");
msg("header is too large");
msg("not an NGCorion backup file");
msg("the backup does not start with its manifest");
msg("the backup has no summary");
msg("the backup is empty");
msg("the database has no migration revision");
msg("the file changed since it was written");
msg("the manifest or summary is missing");
msg("unexpected data after the end of the archive");
msg("unexpected data after the end of the backup");
msg("Command line");
// target catalog (app/core/target_catalog.py): categories and descriptions
msg("Network & security");
msg("Servers & OS");
msg("Containers & virtualisation");
msg("Databases");
msg("Web & application servers");
msg("Directory & network services");
msg("Routers & switches");
msg("Firewall");
msg("Operating system");
msg("Microsoft database");
msg("Document database");
msg("HTTP server");
msg("Domain controllers");
msg("DNS role · DISA STIG");
msg("DHCP role · Microsoft guidance");
msg("Microsoft web server");
// Harden All: credential fields (app/modules/hardening/harden_all/families.py,
// app/modules/benchmark/connectors.py) and remediation parameters
msg("SSH Username");
msg("SSH Password");
msg("SSH Port");
msg("Sudo Password");
msg("Leave empty to reuse the SSH password");
msg("Enable Secret");
msg("Required if the device drops into user EXEC mode on login");
msg("Leave empty to use each finding's own VDOM");
msg("SQL Server Login");
msg("SQL Server Password");
msg("Port");
msg("Windows Username");
msg("Windows Password");
msg("WinRM Port");
msg("Transport");
msg("Confirm the change");
msg("This change has side effects described in the check's warning. Choose 'yes' to apply it.");
msg("yes");
msg("New Administrator Account Name");
msg("New name for the built-in Administrator account");
msg("New Guest Account Name");
msg("New name for the built-in Guest account");
msg("Maximum Password Age (days)");
msg("Maximum days before a password must change (CIS: <= 365, not 0)");
msg("Account Lockout Duration (minutes)");
msg("How long an account stays locked (CIS: >= 15 minutes)");
msg("Account Lockout Threshold (attempts)");
msg("Failed logons before lockout (CIS: 1-5)");
msg("Reset Lockout Counter After (minutes)");
msg("Time before the lockout counter resets (CIS: >= 15 minutes)");
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
