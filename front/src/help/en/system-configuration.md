# System configuration

NGCorion's own settings, one card each. Every secret here (SMTP password, SMS API key, SNMP community and keys, account passwords) is stored encrypted and never shown again; to change it, enter a new value.

## Cards

| Card | Use |
|---|---|
| Time Configurations | Time zone and NTP server; a correct clock matters for two-step sign-in, schedules and the audit trail |
| SNMP Configurations | NGCorion's own SNMP agent, so the organisation's NMS can monitor it |
| Syslog Configurations | Sending the server's OS logs and CEF alerts to a SIEM |
| SMS Configurations | The SMS gateway for alerts |
| SMTP Configurations | Mail server for alerts, scheduled reports and password recovery codes; with "Send test" |
| Certificate Configurations | The web interface's TLS certificate (PEM or PFX); TLS 1.2 and 1.3 only |
| Language | Default interface language for new users |
| Remediation deadlines | The deadline for each severity and the longest risk acceptance |
| Reports | Organisation name and logo on reports, and how long they are kept |
| Pinned device keys | Recorded SSH keys and certificates of the devices; delete only after confirming a change |
| Two-step sign-in | Roles that must use a phone code, and the set-up period |
| Active Directory / LDAP | Sign-in with organisation accounts, roles from domain groups |
| Credential profiles | Encrypted sign-in details for group audits and backups |

## Suggested order after installation

1. Time (the organisation's internal NTP).
2. Certificate (the organisation's certificate for the system's name).
3. SMTP, and send yourself a test email.
4. Two-step sign-in and, if there is a domain, Active Directory / LDAP.
5. Credential profiles, each tested with "Test" on one asset (it only signs in and changes nothing).

## Example: credential profiles

| Name | Kind | Device account | For |
|---|---|---|---|
| `linux-audit` | SSH | `ngc-audit` with a sudo password | Linux servers |
| `netdev-ssh` | SSH | `ngc-audit` with the enable secret | Cisco and FortiGate |
| `win-domain` | WinRM | `CORP\svc-ngc-audit` | Windows, AD, DNS, DHCP, IIS |

A profile's password is write-only; no page returns it. Its change period (90 days by default) raises the alert "Credential profile due for a password change".

## Take care

> Deleting a pinned key means the next connection accepts a new key without asking; delete it only after confirming the key change with the device's owner. Give profiles their own least-privilege account, never a shared admin account. Every change on this page is recorded in the audit trail.

## Read more

- Admin guide, sections 5 and 7 · Training course, lesson 2
