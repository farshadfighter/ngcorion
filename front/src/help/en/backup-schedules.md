# Backup schedules

Backs up the configuration of every device in a group each night (or whenever you choose), with an **SSH credential profile**. "Backup runs" shows the result of each run.

## Make a schedule

1. "New Schedule".
2. **Device type** (Cisco IOS, FortiGate, Linux, Apache, MongoDB), **asset group** and **credential profile**.
3. Devices backed up at the same time.
4. **Recurrence** (every night at 02:00 by default) → "Create".
5. "Run now" so the first backup is taken right away.

## Result of a run

| Result | Meaning |
|---|---|
| First backup | The device had no backup yet |
| Unchanged | Same configuration as before; no new version is stored |
| Changed | With lines added and removed, "by NGCorion" or "outside NGCorion" |
| Failed | Sign-in refused, unreachable, or no IP address |

"Device reported a change" marks a run started by the device's own syslog after a configuration change.

## Immediate backup after a change

If a device sends syslog to NGCorion (Cisco with `%SYS-5-CONFIG_I`, FortiGate with its configuration events), about a minute after a change that device is backed up with this schedule's profile, together with the user name and the address that made the change. If no active schedule covers the device, only the alert "Configuration change reported, no backup taken" comes.

## Keeping

"Remove identical copies after (days)": backups identical to the previous one are removed after this time (90 days by default). Every changed version, the first and last backup of each device, and backups a hardening or restore depends on are always kept.

## Example

"Nightly Cisco backup": type Cisco IOS, group "Cisco devices", profile `netdev-ssh`, every night at 02:00. Each morning, look at "Backup runs": every change "outside NGCorion" should have a change request.

## Take care

> A read-only account is enough; Linux, Apache and MongoDB read the files with sudo, and Cisco needs the enable secret. The permission to use credential profiles is required.

## Read more

- [Backups](/backup) · [Asset groups](/assets/groups)
- User guide, section 9.1 · Training course, lessons 7.1 and 7.2
