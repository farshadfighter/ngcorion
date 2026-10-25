# Alert and notification rules

Decides which events raise an alert, how urgent they are, and who hears about them where: in-app, email, SMS, syslog/SIEM or a webhook. Four tabs: "Rules", "Channels", "Delivery policy" and "Delivery log".

## Create or edit a rule

1. "+ New rule" (or click an existing rule).
2. **Event:** what to watch; some events have parameters (e.g. a CPU threshold or the days before a certificate expires).
3. **"Which assets":** all, by type or zone, or specific assets.
4. **"How urgent":** critical, warning or info.
5. **"Who hears about it":** roles, users, or an outside email address or mobile number.
6. **"Where":** in-app (always), email, SMS, syslog/SIEM, webhook.
7. **"Avoid noise":** "Remind while not acknowledged", "Group bursts" and "SMS quiet hours" (critical alerts are still sent, unless the delivery policy says otherwise). A rule without quiet hours of its own follows those of the "Delivery policy".
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
| SMS | The SMS gateway (Kavenegar, Ghasedak, sms.ir or any HTTP gateway) in System configuration; users' mobile numbers in [Users](/settings/users) |
| Syslog / SIEM | The syslog server of System configuration; CEF, read by ArcSight, QRadar, Splunk and Wazuh without a custom rule |
| Webhook | "+ Webhook": name and URL. NGCorion sends a JSON POST for each message, signed with the signing secret (HMAC-SHA256) |

## Delivery policy

Rules say which alerts go out where; the "Delivery policy" decides once, for every rule, what may go out by email and SMS at all:

| Setting | Use |
|---|---|
| Send alerts by email / SMS | Turns a channel off for every rule (in-app alerts are still raised) |
| Send for | The least severity sent on the channel: every severity, Warning and Critical, or Critical only |
| Quiet hours | The night without SMS, for the rules that set none of their own; server time. "Critical alerts still go out in quiet hours" can be turned off |
| Daily limit | At most this many SMS a day (0 = no limit), so an alert storm cannot use up the SMS credit |
| Password reset code | The "Forgot password" code goes by email, SMS or both. By SMS it goes to the account's mobile number; an account without one, or an installation without an SMS provider, gets it by email |

A message the policy holds back is in the delivery log as Skipped, with the reason. Test messages are not held back. Every change of the policy is in the audit trail.

## Delivery log

Every message with time, channel, recipient and result (sent, failed, "Waiting to retry", skipped with the reason); kept 90 days. If someone did not get an alert, look here first.

## Take care

> A rule without recipients or channels only makes an in-app alert. Too many recipients and frequent reminders get alerts ignored; send each event to someone who can act on it.

## Read more

- [Alerts](/alerts) · Admin guide, section 8.4 · Training course, lesson 13
