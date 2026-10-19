import { t, n, currentLanguage } from "./index";
import { formatDate } from "../utils/dates.js";

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
    // first: more specific than the generic "{{code}} from {{code2}}" further down (the first match wins)
    // configuration changes reported over syslog (app/modules/syslog/config_changes.py)
    msg("{{added_lines}} line(s) added and {{removed_lines}} removed; changed by {{user}} from {{address}} (reported over syslog)"),
    msg("Changed by {{user}} from {{address}}; no scheduled backup covers this device"),
    msg("Configuration change on '{{asset_name}}' reported over syslog by {{who}} from {{where}}; schedule '{{job_name}}' started a backup"),
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
    // device health and restarts (app/modules/noc/health.py, alerts noc.cpu_high ... noc.device_rebooted)
    msg("CPU at or above {{percent}}% for {{minutes}} minutes"),
    msg("Memory at or above {{percent}}% for {{minutes}} minutes"),
    msg("A file system at or above {{percent}}% full"),
    msg("A temperature sensor at or above {{celsius}} °C"),
    msg("CPU at {{value}}%, at or above {{percent}}% for {{minutes}} min"),
    msg("Memory at {{value}}%, at or above {{percent}}% for {{minutes}} min"),
    msg("{{name}} {{value}}% full (and {{more}} more)"),
    msg("{{name}} {{value}}% full"),
    msg("{{name}} at {{value}} °C"),
    // unknown devices (app/modules/noc/endpoints.py)
    msg("MAC {{mac}}, maker {{vendor}}, IP {{ip}}, seen by {{device}}, port {{port}}"),
    msg("{{count}} addresses that are not assets appeared"),
    msg("Ignored the unknown device {{mac}}"),
    msg("No longer ignoring the device {{mac}}"),
    msg("Unknown device discovery turned on, every {{minutes}} minutes"),
    // benchmark policy (app/modules/audit_policy/router.py)
    msg("Asked to make {{what}} of the {{bench}} benchmark optional"),
    msg("Asked to exclude {{what}} of the {{bench}} benchmark"),
    msg("Approved making {{what}} of the {{bench}} benchmark optional"),
    msg("Approved excluding {{what}} of the {{bench}} benchmark"),
    msg("Rejected making {{what}} of the {{bench}} benchmark optional"),
    msg("Rejected excluding {{what}} of the {{bench}} benchmark"),
    msg("Ended the rule making {{what}} of the {{bench}} benchmark optional"),
    msg("Ended the rule excluding {{what}} of the {{bench}} benchmark"),
    // end of life (app/modules/eol/router.py, remediation titles, alert details)
    msg("Updated {{n}} products of the end-of-life catalog from endoflife.date"),
    msg("Imported {{n}} products into the end-of-life catalog"),
    msg("Removed {{name}} from the end-of-life catalog changes"),
    msg("Added the product {{name}} to the end-of-life catalog"),
    msg("Changed the product {{name}} of the end-of-life catalog"),
    msg("Entered the end of support of {{name}} on {{asset_name}}"),
    msg("Removed the end of support of {{name}} on {{asset_name}}"),
    msg("End of support warns {{days}} days ahead"),
    msg("{{what}} is past the end of support"),
    msg("{{what}} gets security fixes only with paid extended support"),
    msg("{{what}} on {{name}}: support ended {{until}}"),
    msg("{{what}} on {{name}}: fixes only with paid extended support, until {{until}}"),
    msg("{{what}} on {{name}}: support ends {{until}}"),
    msg("Vendor support ends within {{days}} days"),
    // API keys (app/modules/api_keys, alert system.api_key_expiring)
    msg("Created the API key {{name}} (account {{account}})"),
    msg("Changed the API key {{name}}"),
    msg("Renewed the secret of the API key {{name}}"),
    msg("Revoked the API key {{name}}"),
    msg("The API key {{name}} stops working {{date}}"),
    msg("An API key of another system stops working within {{days}} days"),
    msg("An API key is valid for at most {{days}} days"),
    msg("An API key cannot have the module {{module}}"),
    msg("An API key can only read the module {{module}}"),
    // TLS certificates (app/modules/tls/router.py, remediation titles, alert details)
    msg("Scanned the TLS certificates of {{name}}"),
    msg("Added the TLS service {{what}} of {{name}}"),
    msg("Turned off the TLS service {{what}} of {{name}}"),
    msg("Turned on the TLS service {{what}} of {{name}}"),
    msg("Changed the server name of the TLS service {{what}} of {{name}}"),
    msg("Removed the TLS service {{what}} of {{name}}"),
    msg("Automatic TLS scan every {{hours}} h on ports {{ports}}; warns {{days}} days before expiry"),
    msg("Automatic TLS scan off; ports {{ports}}; warns {{days}} days before expiry"),
    msg("Trusted the certificate authority {{name}}"),
    msg("No longer trusts the certificate authority {{name}}"),
    msg("The certificate of {{what}} expired on {{date}}"),
    msg("The certificate of {{what}} is not valid before {{date}}"),
    msg("The certificate of {{what}} is self-signed"),
    msg("The certificate of {{what}} is issued by an untrusted authority"),
    msg("The certificate of {{what}} has a weak key ({{key}})"),
    msg("The certificate of {{what}} is signed with {{algorithm}}"),
    msg("The certificate of {{what}} does not name the host"),
    msg("{{what}} still accepts {{protocols}}"),
    msg("The certificate of {{what}} on {{name}} expired {{date}}"),
    msg("The certificate of {{what}} on {{name}} expires {{date}}"),
    msg("A TLS certificate of an asset expires within {{days}} days"),
    // compliance with standards (app/modules/compliance/router.py)
    msg("Assessed requirement {{ref}} of {{name}} by hand"),
    msg("Removed the assessment of requirement {{ref}} of {{name}}"),
    msg("Created the standard {{name}}"),
    msg("Imported the standard {{name}} with {{refs}} requirements"),
    msg("Deleted the standard {{name}}"),
    msg("Added requirement {{ref}} to the standard {{name}}"),
    msg("Changed requirement {{ref}} of the standard {{name}}"),
    msg("Deleted requirement {{ref}} of the standard {{name}}"),
    msg("Changed the standard {{name}}"),
    msg("Turned on the standard {{name}}"),
    msg("Turned off the standard {{name}}"),
    msg("Put the domains of check {{check}} ({{bench}}) back to automatic"),
    msg("Set the domains of check {{check}} ({{bench}})"),
    // LLDP / CDP topology (app/modules/noc/topology_discovery.py)
    msg("{{a}} port {{pa}} to {{b}} port {{pb}} is no longer reported by LLDP/CDP"),
    msg("LLDP/CDP topology discovery turned on, every {{minutes}} minutes, links added to the map automatically"),
    msg("LLDP/CDP topology discovery turned on, every {{minutes}} minutes, links added by hand"),
    msg("Restarted after {{value}} days of uptime"),
    msg("Restarted after {{value}} hours of uptime"),
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
    // CVE database jobs (app/modules/cve/feeds.py, jobs.py)
    msg("Unexpected error: {{error}}. The database was not changed."),
    msg("NVD is not reachable: {{error}}"),
    msg("CISA KEV is not reachable: {{error}}"),
    msg("EPSS is not reachable: {{error}}"),
    // distribution advisories (app/modules/advisories)
    msg("OSV.dev is not reachable: {{error}}"),
    msg("OSV.dev refused the download for {{ecosystem}} (HTTP {{code}}). Google, which hosts OSV.dev, refuses addresses in some countries: set HTTPS_PROXY or OSV_BASE_URL (a mirror) in .env, or download all.zip on another network and import it here."),
    msg("OSV answered HTTP {{code}} for {{ecosystem}}"),
    msg("OSV answered HTTP {{code}} for the change list of {{ecosystem}}"),
    msg("The file is larger than the {{num}} MB limit."),
    msg("Unknown release: {{release}}"),
    // reports
    msg("Not an email address: {{email}}"),
    msg("Building the report failed: {{error}}"),
    msg("SMTP error: {{error}}"),
    msg("{{name}} - {{error}}"),
    // app/core/dependencies.py require_permission
    msg("Insufficient permission: {{permission}} access required for {{module}}"),
    // audit trail details (scripts/audit_messages.py lists them; most specific first)
    msg("Set a temporary password for '{{username}}'; it must be changed at the next sign-in"),
    msg("Installed certificate from '{{source}}' (issued_to={{value}}, expires_at={{value2}}); traefik: {{value3}}"),
    msg("Software collection on {{asset_name}} ({{ip_address}}) failed: could not connect"),
    msg("Software collection on {{asset_name}} ({{ip_address}}) failed: {{reason}}"),
    // SSH connection errors (app/core/ssh_exceptions.py), shown by audits, hardening and collect now
    msg("SSH connection failed to {{device}}: {{reason}}"),
    msg("Authentication failed for {{device}}"),
    msg("Connection timed out to {{device}}"),
    msg("Cannot connect to {{device}}"),
    msg("SSH algorithm negotiation failed with {{device}}"),
    msg("Host key verification failed for {{device}}"),
    // collect now (app/modules/software/router.py)
    msg("WinRM on {{address}} did not answer: {{reason}}"),
    msg("Connected to {{address}}, but reading the software list failed: {{reason}}"),
    msg("Asset ID: {{asset_id}}, Name: {{asset_name}}, IP: {{target_ip}}, Profile: {{profile}}, Compliance: {{compliance_pct}}%"),
    msg("Session: {{id}}, Asset: {{asset_name}}, IP: {{target_ip}}, Profile: {{profile}}, Compliance: {{compliance_pct}}%"),
    msg("Deleted session for Asset ID: {{asset_id}}, Name: {{asset_name}}, IP: {{target_ip}}"),
    msg("Asset: {{asset_name}}, Session: {{id}}, Profile: {{profile}}, Compliance: {{compliance_pct}}%"),
    msg("Deleted session for Asset ID: {{asset_id}}, Name: {{value}}, IP: {{target_ip}}"),
    msg("Updated webhook '{{name}}' and replaced its secret"),
    msg("Restore #{{id}} of backup #{{backup_id}} on {{asset_name}} ({{device_ip}}): {{status}}. Reason: {{reason}}"),
    msg("{{kind}}: {{new}} new, {{changed}} updated, {{removed}} removed, {{kev}} KEV, {{epss}} EPSS"),
    msg("Asset Name: {{asset_name}}, IP: {{target_ip}}, Profile: {{profile}}. Error: {{e}}"),
    msg("Asset Name: {{asset_name}}, IP: {{target_ip}}, Profile: {{profile}}. Error: {{exc}}"),
    msg("Exported {{rows}} security events; filters: {{value}}"),
    msg("Deleted session for Asset ID: {{asset_id}}, IP: {{ip}}"),
    msg("releases kept besides those in use: {{releases}}"),
    msg("Exported risk JSON for asset {{asset_id}} ('{{asset_name}}')"),
    msg("Asset: {{asset_name}}, IP: {{target_ip}}, Profile: {{profile}}, Error: {{e}}"),
    msg("Deleted session: {{session_id}}, Asset: {{asset_name}}, IP: {{target_ip}}"),
    msg("Removed the identification of '{{key}}'"),
    msg("Software collection on {{asset_name}} failed: {{value}}"),
    msg("Restored {{value}} backup; safety backup {{value2}}"),
    msg("Updated SMS settings (provider={{value}})"),
    msg("Deadlines {{value}}, longest acceptance {{value2}}"),
    msg("Collected {{item_count}} items from {{asset_name}} ({{ip_address}}) over {{platform}}"),
    msg("Login successfully with {{role}} Role."),
    msg("Updated SMTP settings (host={{value}}:{{value2}})"),
    msg("Exported {{rows}} sign-ins; filters: {{value}}"),
    // audit storage (app/core/storage_guard.py, app/modules/audit_archive/)
    msg("{{mb}} MB free on {{path}}: changes paused for everyone but system administrators"),
    msg("{{mb}} MB free on {{path}}: changes allowed again"),
    msg("Removed {{events}} audit events and {{logins}} sign-ins older than {{cutoff}}, archived in {{file}} (SHA-256 {{sha}})"),
    msg("plan {{plan_code}}, {{max_assets}} assets, valid until {{offline_until}}"),
    msg("Created user '{{username}}' with role '{{role}}'"),
    msg("Deleted user '{{username}}' with role '{{role}}'"),
    msg("Asset: {{asset_name}}, Profile: {{profile}}, Error: {{e}}"),
    msg("Exported {{value}} software products"),
    msg("Pinned host key of {{name}} cleared"),
    msg("{{where}}, Profile: {{profile}}, Compliance: {{compliance_pct}}%"),
    msg("Updated permissions for '{{username}}'"),
    msg("export: {{cves}} CVEs written to {{file}}"),
    msg("Asset ID: {{asset_id}}, Asset Name: {{asset_name}}"),
    msg("Login successful (role={{role}})"),
    // sign-in with Active Directory / LDAP (app/modules/directory)
    msg("Created directory account '{{username}}' with role '{{role}}' at its first sign-in"),
    msg("Role of '{{username}}' set to '{{role}}' by its directory groups"),
    msg("Permissions of '{{username}}' set by its directory groups"),
    msg("Turned on '{{username}}' again: the directory allows it"),
    msg("Turned off '{{username}}': no longer in the directory"),
    msg("Turned off '{{username}}': disabled in the directory"),
    msg("Turned off '{{username}}': in no mapped directory group any more"),
    msg("{{name}} from {{address}} while directory sign-in is on"),
    msg("{{server}}: the service account was refused (check its name and password)"),
    msg("{{server}}: the server's certificate is not trusted (upload the CA certificate) or does not match its name"),
    msg("{{server}}: the server's certificate does not carry the name used to reach it"),
    msg("{{server}}: no answer in time"),
    msg("{{server}}: the server requires an encrypted connection (choose LDAPS or StartTLS)"),
    msg("{{server}}: connection refused"),
    msg("{{server}}: search failed ({{reason}})"),
    msg("Directory settings incomplete: {{fields}}"),
    msg("Not a server name or address: {{value}}"),
    msg("Unknown module: {{value}}"),
    msg("Tested the directory sign-in of '{{username}}'"),
    // two-step sign-in (app/modules/auth/mfa_router.py)
    msg("Login successful (role={{role}}) with a recovery code; {{left}} left"),
    msg("Login successful (role={{role}}) with a two-step code"),
    msg("Reset two-step sign-in for '{{username}}'; they set it up again at the next sign-in"),
    msg("Two-step sign-in required for: {{roles}}; grace period {{value}} days"),
    msg("{{name}} ({{size}} bytes) queued as job {{id}}"),
    msg("Created zone '{{name}}' (score={{score}})"),
    msg("Restore test of {{filename}} started"),
    msg("Default language set to {{value}}"),
    msg("Updated risk settings: {{value}}"),
    msg("Copied {{filename}} to destinations"),
    msg("automatic update on at {{time}}"),
    msg("Tested rule '{{name}}': {{value}}/{{results}} sent"),
    msg("Applied {{section}} configuration"),
    msg("Cleared system logs: {{deleted}}"),
    msg("Saved with warnings: {{warnings}}"),
    msg("key {{license_key}}, plan {{status}}, {{status2}} assets"),
    msg("Destination {{name}} changed"),
    msg("Destination {{name}} removed"),
    msg("{{kind}}: {{releases}} - {{records}} records, {{rows}} rows"),
    msg("Tested webhook '{{name}}': {{value}}"),
    msg("Restore of {{filename}} started"),
    msg("Acknowledged '{{title}}' ({{source_label}})"),
    msg("Created rule '{{name}}' ({{event_type}})"),
    msg("Turned off rule '{{name}}'"),
    msg("Updated webhook '{{name}}'"),
    msg("Deleted webhook '{{name}}'"),
    msg("Backup #{{id}} queued ({{contents}})"),
    msg("Destination {{name}} added"),
    msg("Changed role to '{{role}}'"),
    msg("Turned on rule '{{name}}'"),
    msg("Updated zone '{{name}}': {{changes}}"),
    msg("Identified '{{match_key}}' as {{what}}"),
    msg("Added webhook '{{name}}'"),
    msg("Test email to {{to}}: {{value}}"),
    msg("Updated rule '{{name}}'"),
    msg("Deleted rule '{{name}}'"),
    msg("Deleted zone '{{zone_name}}'"),
    msg("Upload failed: {{exc}}"),
    msg("Delete failed: {{exc}}"),
    msg("Updated {{changes}} for '{{username}}'"),
    msg("Resolved '{{title}}' ({{source_label}})"),
    msg("Test SMS to {{phone}}: {{value}}"),
    msg("{{value}} {{host}}:{{port}} - removed {{fingerprints}}"),
    msg("Uploaded {{original}} as {{filename}}"),
    msg("Downloaded {{filename}}"),
    msg("asset {{asset_id}}: {{vendor}} {{product}} {{version}}"),
    msg("{{ref}} ({{value}}) until {{expires_at}}"),
    msg("{{filename}}: no match"),
    msg("Checked {{filename}}: {{verify_status}}"),
    msg("{{where}}. Error: {{exc}}"),
    msg("Deleted {{name}}"),
    msg("Test {{channel}}{{value}}: {{value2}}"),
    msg("job {{id}} ({{kind}})"),
    msg("{{ref}} until {{expires_at}}"),
    msg("{{filename}}: match"),
    msg("key {{license_key}}: {{detail}}"),
    msg("{{ref}} on {{asset_name}}: {{value}}"),
    msg("{{code}} from {{code2}}"),
    // asset groups, credential profiles, group audits (app/modules/asset_groups)
    msg("Created asset group '{{name}}'"),
    msg("Changed asset group '{{name}}'"),
    msg("Added {{n}} asset(s) to group '{{name}}'"),
    msg("Removed {{n}} asset(s) from group '{{name}}'"),
    msg("Deleted asset group '{{name}}'"),
    msg("Added tag(s) {{tags}} to {{ids}} asset(s)"),
    msg("Removed tag(s) {{tags}} from {{ids}} asset(s)"),
    msg("Changed the owner of {{changed}} asset(s) in one step"),
    msg("Changed the location of {{changed}} asset(s) in one step"),
    msg("Changed the status of {{changed}} asset(s) in one step"),
    msg("Changed the zone of {{changed}} asset(s) in one step"),
    msg("Deleted {{deleted}} asset(s) in one step"),
    msg("Created credential profile '{{name}}' for user '{{username}}'"),
    msg("Changed the sign-in details of credential profile '{{name}}'"),
    msg("Changed credential profile '{{name}}'"),
    msg("Deleted credential profile '{{name}}'"),
    msg("Tested credential profile '{{name}}' on {{asset_name}} ({{ip_address}})"),
    msg("Started a {{technology}} audit of group '{{name}}' ({{total}} assets) with credential profile '{{name2}}'"),
    msg("Stopped the audit of group '{{group_name}}'"),
    msg("Retried {{n}} failed asset(s) of the audit of group '{{group_name}}'"),
    msg("Scheduled job '{{job_name}}' started a {{technology}} audit of group '{{name}}' with credential profile '{{name2}}'"),
    msg("{{group_name}} ({{technology}}): {{failed}} asset(s) could not be audited"),
    msg("{{name}}: password not changed for {{rotation_days}} days or more"),
    msg("A group run covers at most {{value}} assets"),
    // scheduled device backups (app/modules/backup, group runs of kind "backup")
    msg("Started a {{technology}} configuration backup of group '{{name}}' ({{total}} assets) with credential profile '{{name2}}'"),
    msg("Stopped the configuration backup of group '{{group_name}}'"),
    msg("Retried {{n}} failed asset(s) of the configuration backup of group '{{group_name}}'"),
    msg("Device backups identical to the previous one are kept {{value}} days"),
    msg("Scheduled job '{{job_name}}' started a {{technology}} configuration backup of group '{{name}}' with credential profile '{{name2}}'"),
    msg("{{group_name}} ({{technology}}): {{failed}} asset(s) could not be backed up"),
    msg("{{added_lines}} line(s) added and {{removed_lines}} removed since the previous backup"),
    msg("{{added_lines}} line(s) added and {{removed_lines}} removed ({{change_ref}})"),
    // syslog intake (app/modules/syslog)
    msg("{{n}} message(s), latest: {{latest}}"),
    msg("No syslog message for {{hours}} hours or more (last one at {{last}} UTC)"),
    msg("{{dropped}} message(s) dropped; add the device to the inventory to keep them"),
    msg("Syslog intake is turned on but not receiving: {{reason}}"),
    msg("An asset sends a syslog message at severity {{severity}} or worse (0 emergency ... 7 debug)"),
    msg("An asset that sends syslog has sent nothing for {{hours}} hours"),
    msg("Exported {{rows}} syslog messages"),
    msg("Syslog intake settings: {{protocols}}, kept {{days}} days, at most {{gb}} GB, levels up to {{level}}"),
];

// ── Fixed sentences: translated by exact match ────────────────────────────
msg("Device unreachable");
msg("Interface down");
msg("Interface utilization high");
msg("CPU usage high");
msg("Memory usage high");
msg("Disk almost full");
msg("Temperature high");
msg("Device restarted");
msg("A device's uptime starts again from zero");
msg("CPU usage");
msg("Memory usage");
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
// reports: compliance with a standard (app/modules/reports/templates3.py)
msg("End of life");
msg("Operating systems, firmware and server software past (or close to) the end of their vendor's support.");
msg("Unsupported");
msg("No more fixes from the vendor");
msg("Paid extended support only");
msg("Ending soon");
msg("Not in the catalog");
// reports: TLS certificates (app/modules/reports/templates3.py)
msg("TLS certificates");
msg("Certificates of the assets' TLS services: expired or expiring, untrusted, weak, or still accepting TLS 1.0 and 1.1.");
msg("Expired");
msg("Expire within 90 days");
msg("Other problems");
msg("Trust, key, signature, protocol, name");
msg("All TLS services");
msg("All software");
msg("Compliance with a standard");
msg("Score of a standard (PCI DSS, ISO/IEC 27001, NIST SP 800-53 or the organisation's own), each requirement with its evidence, the gaps and what is assessed by hand.");
msg("Requirements");
msg("Status and score of each");
msg("Gaps");
msg("Failing checks, the most urgent first");
msg("Assessed by hand");
msg("And the requirements still to assess");
msg("Every failed check of every asset");
msg("Standard");
msg("Asset group");
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
msg("the connection was refused (WinRM is not enabled on this port, or a firewall blocks it)");
msg("no answer in time (check the address, the port and the firewall)");
msg("the HTTPS certificate was not accepted (use port 5985 for HTTP, or a trusted certificate)");
msg("the address could not be resolved");
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
msg("Container host · CIS");
msg("Cluster node · CIS");
msg("Open-source database · CIS");
msg("Hypervisor host · CIS");
msg("Web server and reverse proxy · CIS");
msg("Firewall · Sophos guidance");
msg("HTTPS API");
msg("API Username");
msg("API Password");
msg("API Port");
msg("Failed logins before blocking");
msg("Unsuccessful administrator logins from one address before it is blocked (1-5).");
msg("Minimum administrator password length");
msg("Characters an administrator password needs at least (12-20).");
msg("Maximum request body size");
msg("client_max_body_size for the whole server: a number with k, m or g (CIS suggests 100k; uploads need more).");
msg("Large header buffers");
msg("large_client_header_buffers: number and size (CIS suggests 2 1k; sites with large cookies need 4 8k).");
msg("Connections per address");
msg("Simultaneous connections allowed from one client address.");
msg("Requests per second per address");
msg("Sustained request rate allowed from one client address.");
msg("Request burst");
msg("Requests above the rate accepted at once before nginx answers 503.");
msg("Content Security Policy");
msg("default-src-self: content only from the site itself; -no-framing also forbids embedding the site in frames.");
msg("Referrer policy");
msg("What browsers send in the Referer header when leaving the site.");
msg("NTP servers");
msg("Comma-separated NTP servers (host names or addresses).");
msg("Remote syslog collector");
msg("Collector URL: ssl://host:1514, tcp://host:514 or udp://host:514.");
msg("Login banner text");
msg("Warning shown on the DCUI and before SSH login.");
msg("SSH + MySQL login");
msg("MySQL Username");
msg("MySQL Password");
msg("MySQL Port");
msg("Connections per account");
msg("Maximum simultaneous connections for one MySQL account (0 = unlimited).");
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
msg("Terminated pod GC threshold");
msg("How many terminated pods the cluster keeps before garbage collection (Kubernetes default 12500).");
msg("Pod PIDs limit");
msg("Maximum number of processes per pod on this node.");
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
// sessions and passwords (app/modules/auth/router.py, app/core/dependencies.py)
msg("The current password is incorrect.");
msg("The new password must be different from the current one.");
msg("Password change required: choose your own password before continuing.");
msg("Session has ended. Please login again.");

// sign-in with Active Directory / LDAP (app/modules/directory, app/modules/auth/router.py)
msg("Local administrator signed in while directory sign-in is on");
msg("The account is disabled in the directory");
msg("The account is in no directory group mapped to an NGCorion role");
msg("Directory not reachable");
msg("The directory could not be reached");
msg("Turned on sign-in with the organization's directory");
msg("Turned off sign-in with the organization's directory");
msg("Changed the directory sign-in settings");
msg("Directory sign-in uses plain LDAP: passwords cross the network unencrypted");
msg("Connected and signed in as the service account");
msg("Connected, but the base DN was not found");
msg("Map at least one directory group to a role before turning directory sign-in on");
msg("Directory sign-in is off");
msg("Sign-in with your organization account is not available right now. Try again in a few minutes or ask an administrator.");
msg("Your password is managed by your organization's directory. Change it there.");
msg("This account signs in through the directory; its password is changed there");
msg("This account comes from the directory: its name, password, role and permissions are set there and by the group mapping");
msg("The directory cannot be reached to check your password. Try again later.");
msg("A filter must be in parentheses, e.g. (objectClass=user)");
msg("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----)");
msg("no directory server is configured");
msg("Local administrator signed in");
msg("Sign-in with Active Directory / LDAP cannot reach any directory server");
msg("A local administrator account signs in while sign-in goes through the directory");
msg("Directory account check");

// two-step sign-in (app/core/mfa.py, app/modules/auth/mfa_router.py)
msg("The code is not correct.");
msg("The sign-in step has expired. Sign in again.");
msg("Enter a code from your current authenticator app.");
msg("Start the setup again.");
msg("The code is not correct. Check the phone's clock and try the next code.");
msg("Two-step sign-in is not on.");
msg("Your role must use two-step sign-in. To move it to a new phone, set it up again.");
msg("Manage your own two-step sign-in from your account menu");
msg("Two-step sign-in required: set it up before continuing.");
msg("Two-step sign-in was reset");
msg("Turned on two-step sign-in");
msg("Moved two-step sign-in to a new authenticator app");
msg("Made new recovery codes");
msg("Turned off two-step sign-in");
msg("Wrong password for a two-step sign-in change");
msg("Wrong two-step code");
msg("Password accepted; waiting for the two-step code");

// disk nearly full (app/core/storage_guard.py)
msg("The server is almost out of disk space: changes are paused until a system administrator frees space.");

// temporary password set by an administrator (app/modules/users/service.py reset_password)
msg("Only system administrators can set a temporary password");
msg("Change your own password from your account menu");

// audit trail details without values (scripts/audit_messages.py)
msg("Password changed by the user");
msg("Password reset code generated");
msg("Password reset via emailed OTP");
msg("Current password was wrong");
msg("No active account for email");
msg("Invalid or expired reset code");
msg("Rate limited");
msg("report settings changed");
msg("Backup settings changed");
msg("Backup passphrase set");
msg("Restore refused: wrong password");
msg("Backup passphrase change refused");
msg("Removed the installed certificate and key");
msg("NVD API key set");
msg("automatic update off");
msg("automatic advisory updates on");
msg("automatic advisory updates off");
msg("no reason given");
msg("every asset");
msg("nothing");
msg("none");
msg("no release");

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

// A value written in Latin letters (a device, port, user or product name) inside a Persian sentence:
// first-strong isolated, so the bidi algorithm keeps it whole and in place instead of moving its
// digits and punctuation ("core-sw-01 port Gi1/0/2" no longer reads "01 ... Gi1/0/2 core-sw").
// Values with Persian in them, and ones n() already isolated, are left alone.
const LATIN = /[A-Za-z]/;
const PERSIAN = /[\u0600-\u06FF]/;
const isolate = (value) => (currentLanguage() === "fa" && typeof value === "string" && LATIN.test(value)
    && !PERSIAN.test(value) && !/^[\u2066-\u2068]/.test(value) ? `\u2068${value}\u2069` : value);

// A day the API wrote as 2028-04-26 reads as a date of the UI's calendar ("۶ اردیبهشت ۱۴۰۷").
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const value = (raw) => (DAY.test(raw) ? formatDate(raw) : isolate(n(tb(raw))));

/** Translate one English sentence from the API; unknown text comes back unchanged. */
export function tb(text) {
    if (typeof text !== "string" || !text) return text;
    const exact = t(text);
    if (exact !== text) return exact;
    for (const { key, names, re } of COMPILED) {
        const m = re.exec(text);
        if (!m) continue;
        const values = Object.fromEntries(names.map((name, i) => [name, value(m[i + 1])]));
        return t(key, values);
    }
    return text;
}

/** An audit trail detail: one sentence, or several joined with "; " ("NVD API key set; automatic update off"). */
export function tbDetail(text) {
    const whole = tb(text);
    if (whole !== text || typeof text !== "string" || !text.includes("; ")) return whole;
    const parts = text.split("; ");
    const shown = parts.map(tb);
    // a record of values ("rows=3; filters=...") keeps its own separators
    if (shown.every((part, i) => part === parts[i])) return text;
    return shown.join(currentLanguage() === "fa" ? "؛ " : "; ");
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

// asset groups, credential profiles, group audits (app/modules/asset_groups)
msg("Group audit finished with failures");
msg("A group audit ends with assets that could not be audited");
msg("A group backup ends with devices that could not be backed up");
msg("Credential profile due for a password change");
msg("A credential profile's password is older than its change period");
msg("Group audits");
msg("Group not found");
msg("A group with this name exists");
msg("Assets join a dynamic group through its rules");
msg("Scheduled audits use this group: delete them first");
msg("A group audit of this group is running");
msg("Enter at least one tag");
msg("Unknown status");
msg("Choose an owner or location that exists");
msg("Zone not found");
msg("Type the number of assets to confirm the deletion");
msg("Credential profile not found");
msg("A credential profile with this name exists");
msg("The kind of a credential profile cannot change");
msg("Scheduled audits use this profile: change or delete them first");
msg("A group audit with this profile is running");
msg("The asset has no IP address");
msg("Group audit not found");
msg("The group audit is not running");
msg("The credential profile was deleted");
msg("The asset was deleted");
msg("Wait for the run to finish or stop it first");
msg("The group has no assets");
msg("This technology cannot be audited with a credential profile");
msg("The credential profile is of a different kind than the technology needs");
msg("Enter the password");
msg("A port is a number from 1 to 65535");
msg("Unknown WinRM transport");
msg("Unknown profile kind");
msg("Unknown secret field");
msg("A secret is at most 1024 characters");
msg("A tag is 1 to 64 characters");
msg("NGCorion restarted while this audit was running");
msg("The group or credential profile of this schedule no longer exists");
msg("Internal error");
msg("Not a number");

// scheduled device backups (app/modules/backup)
msg("Configuration changed outside NGCorion");
msg("A device's configuration differs from its previous backup and NGCorion did not change it");
msg("Configuration changed by NGCorion");
msg("A device's configuration changed through a hardening or restore run by NGCorion");
msg("Group backup finished with failures");
msg("Scheduled backup failed");
msg("Group run not found");
msg("The group run is not running");
msg("This device type cannot be backed up");
msg("The device returned an empty configuration");
msg("NGCorion restarted while this asset was being processed");
msg("Compare two backups of the same asset");

// syslog intake (app/modules/syslog)
msg("Severe syslog message");
msg("Asset stopped sending syslog");
msg("Syslog from an address outside the inventory");
msg("Syslog intake not listening");
msg("An address that is not an asset sends syslog (its messages are dropped)");
msg("Syslog intake is turned on but the port cannot be opened or the listener stopped");
msg("Severity (0 emergency, 1 alert, 2 critical, 3 error, 4 warning)");
msg("Quiet for");
msg("Syslog intake turned on");
msg("Syslog intake turned off");
msg("Backup on a reported configuration change turned on");
msg("Backup on a reported configuration change turned off");
msg("Configuration change reported, no backup taken");
msg("A device reports a configuration change over syslog and no scheduled backup covers it");
msg("Choose UDP, TCP or both");
msg("the listener is not running");
msg("Syslog intake");
msg("group_id and credential_profile_id are required for a backup job");

// unknown devices (app/modules/noc/endpoints.py)
msg("New device on the network");
msg("New devices on the network");
msg("An address that is not an asset appears in the ARP or MAC table of a monitored router or switch");
msg("Unknown device discovery turned off");
msg("No such device");
msg("This device is already an asset");
msg("Unknown asset type");

// benchmark policy (app/modules/audit_policy)
msg("This rule is not waiting for a decision");
msg("Only administrators and managers can decide on a policy rule");
msg("You cannot decide on your own request");
msg("Only an administrator can decide on a whole level or on excluding a high or critical check");
msg("The expiry must be in the future");
msg("No audit of this benchmark has reported this check");
msg("A rule for this check and scope is already pending or in force");
msg("No such rule");
msg("You cannot end this rule");
msg("Unknown benchmark");
msg("Choose one check or one level");
msg("Choose optional or excluded");

// LLDP / CDP topology (app/modules/noc/topology_discovery.py)
msg("Network link lost");
msg("A link found over LLDP/CDP is no longer reported by the devices");
msg("LLDP/CDP topology discovery turned off");
msg("No such neighbour");
msg("This neighbour is not an asset yet");
msg("This neighbour is already an asset");

// end of life (app/modules/eol, alerts software.end_of_life*)
msg("Software past the end of support");
msg("Software support ends soon");
msg("An operating system, firmware or server software of an asset no longer gets fixes from its vendor");
msg("Days before the end");
msg("Only administrators can change the end-of-life catalog");
msg("endoflife.date could not be reached; import a file instead");
msg("The file is larger than 5 MB");
msg("The file is not JSON");
msg("The file is neither an NGCorion end-of-life catalog nor an endoflife.date answer");
msg("A product has no key");
msg("Only a downloaded, imported or own product can be removed");
msg("Two release cycles have the same name");
msg("A product with this name already exists");
msg("Product not found");
msg("Entry not found");
msg("Give the software names the product is found under");

// API keys (app/modules/api_keys, app/core/api_keys.py)
msg("API key expires soon");
msg("API key not found");
msg("A revoked key cannot be changed");
msg("A revoked key cannot be renewed");
msg("Give the key at least one module");
msg("Invalid API key");
msg("API key has expired");
msg("This API key is not allowed from this address");

// TLS certificates (app/modules/tls, alerts tls.certificate_*)
msg("Asked for a scan of every TLS certificate");
msg("Certificate expired");
msg("Certificate expires soon");
msg("A TLS service of an asset presents an expired certificate");
msg("Only administrators can change the TLS certificate settings");
msg("TLS service not found");
msg("The asset has no address: enter the host");
msg("This TLS service is already listed");
msg("A service the scan found comes back with the next scan: turn it off instead");
msg("Certificate authority not found");
msg("This certificate authority is already trusted");
msg("The file is not a PEM certificate");
msg("This certificate is not a certificate authority");
