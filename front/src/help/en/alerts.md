# Alerts

What needs attention now, from every module: a device is down, a vulnerability is exploited, a configuration changed outside NGCorion, a certificate expired, a backup failed and so on. Acknowledging an alert tells the team you are on it.

## Handle an alert

1. Find it in the list (or from the bell at the top of the page).
2. Click it; its link opens the related page with the same filter.
3. **"Acknowledge":** you have seen it and are working on it. Reminders stop.
4. After the fix, **"Resolve"**. If the problem is still there, a new alert is raised at the next check.

Many alerts close on their own when the problem goes away ("recovered by itself").

## Severities

| Severity | Meaning |
|---|---|
| Critical | Urgent; e.g. an exploited vulnerability or a vital device down |
| Warning | Look at it today |
| Info | For awareness; no immediate action |

## Example

An alert "Configuration changed outside NGCorion" for `core-sw`, with user `netadmin` and address `10.20.8.15`:

1. "Acknowledge".
2. The alert's link opens the comparison of the two configuration versions; see what changed.
3. If the change has an approved request, resolve the alert; if not, treat it as a security incident.

## Who receives alerts?

This page is for everyone. Sending alerts by email, SMS, to a SIEM or a webhook is set by the [notification rules](/settings/notifications). For SMS, your mobile number must be on your account.

## Read more

- [Notification rules](/settings/notifications)
- User guide, section 15 · Training course, lesson 13
