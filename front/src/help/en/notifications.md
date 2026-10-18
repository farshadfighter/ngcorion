# Alert and notification rules

Decides which events raise an alert, how urgent they are, and who hears about them where: in-app, email, SMS, syslog/SIEM or a webhook. Three tabs: "Rules", "Channels" and "Delivery log".

## Create or edit a rule

1. "+ New rule" (or click an existing rule).
2. **Event:** what to watch; some events have parameters (e.g. a CPU threshold or the days before a certificate expires).
3. **"Which assets":** all, by type or zone, or specific assets.
4. **"How urgent":** critical, warning or info.
5. **"Who hears about it":** roles, users, or an outside email address or mobile number.
6. **"Where":** in-app (always), email, SMS, syslog/SIEM, webhook.
7. **"Avoid noise":** "Remind while not acknowledged", "Group bursts" and "SMS quiet hours" (critical alerts are still sent).
8. "Send a test", then "Save rule".

## Suggested rules

| Event | Recipient | Where |
|---|---|---|
| Exploited vulnerability on an asset | Security lead and analyst | Email and SMS |
| Configuration changed outside NGCorion | Network engineer | Email |
| Device unreachable (vital devices) | Network engineer | SMS |
| Certificate expired / expires soon | The service owner | Email |
| Remediation overdue | Security lead | Email |
| License problem, disk space low, NGCorion backup failed | System administrator | Email and SMS |
| Every critical event | — | Syslog / SIEM |

## Channels

| Channel | Set up |
|---|---|
| Email | The SMTP server in [System configuration](/settings/system) |
| SMS | The SMS gateway in System configuration; users' mobile numbers in [Users](/settings/users) |
| Syslog / SIEM | The syslog server of System configuration; CEF, read by ArcSight, QRadar, Splunk and Wazuh without a custom rule |
| Webhook | "+ Webhook": name and URL. NGCorion sends a JSON POST for each message, signed with the signing secret (HMAC-SHA256) |

## Delivery log

Every message with time, channel, recipient and result (sent, failed, "Waiting to retry"); kept 90 days. If someone did not get an alert, look here first.

## Take care

> A rule without recipients or channels only makes an in-app alert. Too many recipients and frequent reminders get alerts ignored; send each event to someone who can act on it.

## Read more

- [Alerts](/alerts) · Admin guide, section 8.4 · Training course, lesson 13
