# Report schedules

Reports built and emailed automatically. Each schedule runs with its owner's permissions at the time it runs.

## Make a schedule

1. "New schedule from a report" (or "Save as a schedule…" on [Build a report](/reports)).
2. The report settings with a **moving period** (e.g. "last month").
3. **When:** daily, weekly, monthly (day of the month) or quarterly, with the time.
4. **Recipients**, and whether the file is attached.

## Manage

- **"Run now":** built and sent right away.
- **Enabled/disabled:** switch it off for a while without deleting it.
- **Delete:** reports it already built stay in the archive.
- A failed run raises the alert "Scheduled report failed".

## Example

| Schedule | Template | When | Recipients |
|---|---|---|---|
| Monthly management report | Executive summary, PDF, Persian | Day 1 of every month at 08:00 | CEO, security lead |
| Weekly vulnerabilities | CVE, Excel | Every Saturday at 07:30 | Security team |

## Take care

> A schedule runs with its owner's permissions; if their account is disabled or loses permissions, the report comes out incomplete or fails. To send email, SMTP must be set in System Configuration.

## Read more

- User guide, section 13 · Training course, lesson 14.3
