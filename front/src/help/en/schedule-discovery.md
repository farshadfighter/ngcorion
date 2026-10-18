# Discovery schedules

Repeats the [Auto discovery](/assets/discovery) scan at set times so new hosts on the network are found without anyone having to remember.

## Make a schedule

1. "New Schedule".
2. **Job name** and **target (IP / CIDR / range)**, e.g. `10.20.0.0/16`.
3. **Scan type:** well-known ports, all ports or custom.
4. **Recurrence:** once, hourly, daily or weekly; with hour, minute and, for weekly, the day of the week.
5. "Create".

## Manage

- **"Run now":** runs it once right away.
- **"History":** the result of each run (success, failed, running) with its message.
- **"Enabled":** turn it off for a while without deleting it.
- Each run's result comes to [Auto discovery](/assets/discovery) for approval like a manual scan; nothing becomes an asset by itself.

## Example

"Weekly server network discovery": target `10.20.1.0/24`, well-known ports, weekly on Friday at 02:00. Every Saturday morning, review the new hosts in Auto discovery.

## Take care

> Run it at a quiet hour and avoid scheduled "All ports" scans of large networks.

## Read more

- User guide, section 6.3 · Training course, lesson 3.4
