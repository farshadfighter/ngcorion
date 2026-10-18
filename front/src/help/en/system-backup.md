# NGCorion system backup

A complete, encrypted backup of NGCorion's own data and settings (assets, audits, users, the audit trail …). Configuration backups of network devices are separate, under [Device Backups](/backup). System administrators only.

## Set up (once)

1. **Backup passphrase:** "Set the passphrase…". Every backup is encrypted with it. **Without it no backup can be opened, not even by NGCorion support.** Keep it outside this server (the organisation's password vault).
2. **Destinations:** "Add destination": SFTP or a Windows share (SMB), with an account that may only write to that folder → "Save and test". The SFTP host key is pinned on the first connection.
3. **Schedule and retention:** "Automatic backup" daily or weekly, and "How many to keep" (daily, weekly, monthly).
4. Turn on the **"Weekly restore test"**: the latest full backup is restored into a temporary database and checked, without touching the running system.
5. "Back up now" to make the first backup.

## Tabs

| Tab | What |
|---|---|
| Backups | Each backup with time, type, contents, size and health; "Download", "Send again" to the destinations, and "Restore…" |
| Schedule and retention | Automatic backup, how many to keep, and the restore test |
| Destinations | SFTP and SMB and whether they are reachable |
| Restores and tests | The record of restores and restore tests |

## Full restore

1. "Restore…" on a backup, or "Restore from a file…" for a `.ngbak` file from another server.
2. **Check and passphrase:** every part's health is checked; if the backup was made with another passphrase, give that one.
3. **Confirm:** read "What gets replaced". Anything recorded after the backup's time is lost.
4. The system first takes a safety backup, goes into maintenance mode and comes back when done.

A backup from an older version is upgraded after the restore; one from a newer version is refused. Restoring onto another server works too.

## Take care

> Set at least one destination outside this server; a backup kept only here is lost with the server. Turn on the alerts "NGCorion backup failed", "No recent NGCorion backup" and "Backup restore test failed" for yourself.

## Read more

- Admin guide, section 10 · Training course, lessons 2.4 and 17.1
