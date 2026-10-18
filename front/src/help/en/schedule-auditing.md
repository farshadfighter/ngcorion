# Audit schedules

Repeats audits at set times so compliance is always current and changes are seen early.

## Make a schedule

1. "New Schedule".
2. **Job name** and **technology**.
3. **What to audit:**
    - **"An asset group, with a credential profile"** (recommended): group, profile and benchmark profile. No password is stored in the schedule, and each run audits the assets in the group at that moment.
    - **"One asset, with the credentials typed here":** because the job runs unattended, the credentials are stored encrypted.
4. **Recurrence:** once, hourly, daily or weekly; with hour and minute, and for weekly the day of the week.
5. "Create".

## Manage

- "Run now", "History" (each run's result) and "Enabled" to switch it off for a while.
- A failed run raises the alert "Scheduled job failed".

## Example

"Weekly Linux server audit": group "Linux servers", profile `linux-audit`, weekly on Thursday at 22:00. A new server added to the group is in the next run automatically.

## Take care

> Delete a schedule with typed-in credentials once it is no longer needed, so its password is removed too. The group-and-profile way is safer: a password change happens in one profile only.

## Read more

- [Group audits](/audit/group-runs)
- User guide, section 7.5 · Training course, lesson 5.2
