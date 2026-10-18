# Asset groups

A named set of assets for work on many at once: group audits, scheduled backups, the scope of a benchmark policy, the scope of compliance and reports. A **dynamic** group fills itself from conditions and is always current; a **static** group is filled by hand.

## Make a dynamic group

1. "New group" → name and description.
2. "Dynamic: by conditions".
3. "+ Add condition": field (asset type, zone, owner, location, status, OS, vendor, name, tag, IP range), condition and value. All conditions must hold.
4. Below the conditions, the assets that match now are listed; check them.
5. "Save group".

## Make a static group

1. "New group" → "Static: chosen by hand".
2. "Add assets" and search by name or IP.
3. "Save group". From the [Asset list](/assets/inventory) you can also tick rows and use "Add to group".

## Examples

| Group | Kind | Condition |
|---|---|---|
| Card data environment | Dynamic | IP range `10.20.5.0/24` |
| Linux servers | Dynamic | Type: server; OS: Ubuntu or RHEL |
| Cisco devices | Dynamic | Vendor: Cisco |
| Hardening pilot | Static | `web-01`, `web-02` |

## Dynamic or static?

- Prefer **dynamic**: a new asset that matches joins on its own and is in the next audit or backup run.
- **Static** suits temporary, hand-picked lists (a pilot, for example).
- A group with no condition means "every asset".

## Take care

> A group used by a schedule cannot be deleted. Deleting a group does not touch its assets. Changing the conditions of a group a schedule uses changes the assets of its next run.

## Read more

- [Group audits](/audit/group-runs) · [Backup schedules](/backup/schedules)
- User guide, section 6.2.1 · Training course, lesson 3.6
