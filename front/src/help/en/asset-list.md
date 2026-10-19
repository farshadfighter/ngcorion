# Asset list

Every server, network device, database and service NGCorion knows about. Every other part of the product builds on this list: audits and backups run against an asset, syslog is accepted only from an asset's address, and risk is computed from the asset's zone and importance.

## Main tasks

1. **Add an asset:** "Add asset" → name, host name, IP address, type, OS, location, owner, zone and importance.
   Only the name and type are required; everything else (serial number, value, …) can be added later. The last audit and last hardening dates fill themselves when an audit of the asset completes and when a hardening change on it succeeds.
2. **Add many:** "Download Template" → fill in the Excel file → "Import". Wrong rows are reported with the reason.
3. **Change many:** tick several rows; the bar above the table changes tags, owner, location, status, zone and group at once.
4. **See everything about one asset:** click its name (risk, audits, vulnerabilities, backups, monitoring and timeline).

## Example

| Field | Value |
|---|---|
| Name | `pay-app` |
| IP address | `10.20.5.10` |
| Type | Server · Ubuntu 22.04 |
| Zone | Card data environment |
| Importance | High |
| Host | `esx-01` (it is a virtual machine) |

With a dynamic group "Card data environment" on `10.20.5.0/24`, `pay-app` is a member automatically.

## Take care

> Enter the IP address exactly: syslog and SNMP monitoring are tied to the asset by it. Deleting an asset also deletes the records that depend on it; for an asset taken out of service, set its status to "Decommissioned" instead.

## Common problems

| Situation | Cause |
|---|---|
| "License asset limit" | The number of assets reached the license limit. |
| "Outside license" badge | Audits and hardening do not run on this asset. |

## Read more

- [Asset groups](/assets/groups) · [Auto discovery](/assets/discovery)
- User guide, section 6.2 · Training course, lesson 3
