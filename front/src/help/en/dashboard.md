# Dashboard

The organisation's security at a glance, in five rows: the security risk score and what makes it up, what needs action now, how much of the estate each module covers, where risk and compliance have been heading over 90 days, and the ten riskiest assets. Every card and row opens the page behind it. You see only the parts of the modules you may read.

## Score and its parts

**Security Risk Score** is the organisation's risk from 0 to 100; higher is worse. The bar shows its band and "Average asset risk" how the average risk of the assets changed in the last 30 days (green when it fell).

Below it: **Assets in the inventory** (every asset in the asset list), **Critical Risk Assets** (assets whose calculated risk level is critical, 81 or more) and **Internet Exposed Assets** (assets in the Internet/public or DMZ zone).

**What makes up the score** lists the six parts with their risk and their weight: asset health, audit compliance, hardening, risk intelligence, exposure intelligence and vulnerability. Click a part to open its module. A part marked ! has no data yet and counts as 50 until it has.

## Needs action

Only what is above zero is shown, the most urgent first; click a card to open the list it counts.

| Card | Opens |
|---|---|
| Assets with exploited vulnerabilities (KEV) | [CVE findings](/cve) |
| Critical alerts not acknowledged | [Alerts](/alerts), critical only |
| Monitored devices not answering | [NOC hosts](/noc/hosts) |
| Last backup of NGCorion failed (administrators) | [System backup](/settings/system-backup) |
| Overdue remediation items | [Remediation](/remediation), Overdue view |
| Expired certificates · Certificates expiring within 30 days | [TLS certificates](/cve/certificates) |
| Assets on unsupported software (end of life) | [Software](/assets/software), End of life tab |
| Devices changed outside NGCorion this week | [Backups](/backup) |
| Scheduled discoveries, audits or backups that failed | their schedules page |
| Risk acceptances or benchmark policy rules waiting for your approval (managers and administrators) | the register to approve them |

"Nothing needs action right now in the modules you can see." means every count is zero.

## Coverage and trends

| Figure | Meaning |
|---|---|
| Audited in the last 90 days | Assets with an audit in the last 90 days, of all assets |
| Configuration backed up in the last 30 days | Devices with a recent backup, of the devices that can be backed up |
| Monitored over SNMP | Assets with SNMP settings, of all assets |

The bar is green from 80%, yellow from 50%, red below.

"Last 90 days" draws the average asset risk and the average compliance, one point every 5 days. Each point takes the latest value of every asset at that moment, so an asset audited ten times still counts once. The chip beside the title is the change over the last 30 days.

## Risk scale

| Score | Level |
|---|---|
| 0 to 9 | Minimal |
| 10 to 24 | Low |
| 25 to 39 | Moderate |
| 40 to 59 | High |
| 60 to 100 | Critical |

This scale is for the organisation's score. An asset's own level (in the table and in Critical Risk Assets) uses the risk module's levels: critical from 81.

"Some inputs are incomplete, so this score is provisional." means some assets have not been audited yet or their details are incomplete.

## A suggested daily routine

1. Work through "Needs action" from the first card: alerts and exploited vulnerabilities first.
2. In "Top 10 risky assets", open the worst asset; "Main factor" tells you what to fix first (for example Vulnerability: patch; Audit Risk: fix the failed controls).
3. Once a week, look at coverage and the trends: an asset that is not audited or backed up is a blind spot.

## Take care

> The dashboard counts only what the modules already know: an asset that was never audited or scanned adds nothing to "Needs action". Raise coverage first.

## Read more

- [Risk overview](/risk/overview) · [Risk of assets](/risk/assets) · [Alerts](/alerts) · [Remediation](/remediation)
- User guide, section 5 · Training course, lesson 10
