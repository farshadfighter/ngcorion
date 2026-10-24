# Backups

Each device's saved configuration, version by version: manual backups, before hardening, before a restore, scheduled, and after a change the device itself reported. Compare changes here and restore a configuration when needed.

## Main tasks

- **Manual backup:** "New Backup" → asset, device type, SSH user name and password (and for Cisco the enable secret) → "Take Backup". Credentials are not stored. The list has every asset with the device type told from its type, vendor and system (or from its last backup); choosing an asset sets the device type, which you can change (MongoDB on a Linux host, say). An asset whose type cannot be told asks you to choose it; one without an IP address cannot be chosen.
- **See the versions:** "View Backups" on the device. The "Changes only" filter shows only changed versions.
- **What changed:** each version against the previous one; or tick two versions and "Compare selected".
- **Who changed it:** changes from hardening or a restore are "by NGCorion", the rest "outside NGCorion". If the device reported the change by syslog, the user name and their address are shown too.

## Restore (manager or system administrator only)

1. The backup you want → "Restore".
2. **Connect:** SSH credentials → "Connect & compare →". The device's live configuration is read; nothing is written yet.
3. **Review changes:** exactly which lines will be set and removed. "Possible lock-out." means the change touches management access.
4. **Safety & confirm:** write the reason and set the **auto-revert** time.
5. Run: a backup of the current state, only the changed lines applied, "Reconnect and verify", and "Save on device". If access is lost and verification does not happen, the device returns to its previous configuration by itself.

## Example

At 14:05 user `netadmin` changed an ACL on `core-sw` and the alert "Configuration changed outside NGCorion" came. "What changed" shows the new line `permit tcp 10.20.8.0 0.0.0.255 any eq 22`. There is no change request, so the team lead restores the backup from before 14:05 with the reason "revert ACL change without a change request".

## Take care

> Deleting a backup cannot be undone. An unchanged configuration is not stored again; only the "still the same" date of the latest version is updated. Cisco and FortiGate configurations are compared as a tree, so dates and counters that change on every read are not counted as changes.

## Read more

- [Backup schedules](/backup/schedules) · [Restore history](/backup/restores)
- User guide, section 9 · Training course, lesson 7
