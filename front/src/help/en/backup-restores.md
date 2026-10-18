# Restore history

Every device configuration restore: who ran it and why, what changed on the device, and how it ended. Restores start from the [Backups](/backup) page; this is their record.

## Results

| Result | Meaning |
|---|---|
| Succeeded | Changes applied, access came back, the configuration matched the backup and was saved on the device |
| Reverted | Access was lost or verification failed after the restore, and the device went back to its previous configuration by itself |
| Failed | The restore did not complete; nothing was left changed on the device |
| In progress | Not finished yet |

## Filters

Result, period (30 days, 90 days, 12 months, all) and a search over device, user or reason. Open a row for the timeline of the steps, the number of changed lines, the "Undo point" (the backup taken before the restore) and the duration.

## What to do from here

- Look into every "Reverted" restore: it usually means the change touched management access.
- In the weekly review, match the reasons against change requests.
- Turn on the "Restore failed or reverted" alert for the network lead.

## Read more

- User guide, section 9 · Training course, lesson 7.4
