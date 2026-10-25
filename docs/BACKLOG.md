# Backlog

What is left to do, in the agreed order, and what is known to be incomplete. Updated in the same
commit as the work it describes: an item moves to "Done" with its commit, a new limit or bug found
in testing is added here before it is fixed or deferred. Persian guides describe what is shipped;
this file describes what is not (yet).

## Now: improvements before phase D

| # | Improvement | State |
|---|---|---|
| I1 | Latin names (devices, ports, users, products) inside Persian sentences from the server (alerts, audit trail) kept whole and in place: first-strong isolation in `tb()` | done (3ac5ec3) |
| I2 | Topology nodes draw the device's real interfaces (from the NOC poll) instead of the generic port catalog, so a link found over LLDP/CDP sits exactly on its port | done (f0f10f8) |
| I3 | Cisco IOS MAC tables of every VLAN: read the VLAN list (CISCO-VTP-MIB) and each VLAN's BRIDGE-MIB table (`community@VLAN` on v2c, context `vlan-<id>` on v3) | done (6ed4f95) |
| I4 | From testing: the Iran time zone was hard to find (a bare list of 418 IANA names, nothing selected); no sms.ir provider; no policy for what goes out by email and SMS, and the reset code by email only | done (this commit) |

Bugs reported from testing on the customer test server go before everything else here.

## Next

Phase D is done (items 9, 15, 10, 14, 11, 12), with the product overview and training course
(b959ac1). The final verification is done (b3473cb): full test suite green, 54 pages checked in
English and every main page at phone width in both languages; the header, table and button
layout problems it found are fixed. In-app help for every page (fa and en, in the global search
too) was added on request before the bug list. Next: the bugs reported from testing.

## Known limits (shipped, documented, not yet improved)

- Unknown devices: per-VLAN MAC tables on Cisco IOS are read for up to 64 VLANs per switch; on SNMP v3
  the switch must give the user the `vlan-<id>` contexts.
- Topology: an asset not polled over SNMP (or with more than 96 physical ports) still draws the generic
  port catalog of its type; a link to it is anchored on the catalog port with the same number.
- Unknown devices / topology: tested against snmpsim and net-snmp agents, not yet on real switches.
- Benchmark policy: a rule names a check by its number in the audit module; if a later benchmark
  version renumbers a check, the rule has to be asked for again under the new number.
- Compliance: checks are put in security domains from their titles (about 6% of the checks land in none
  and count only for secure configuration as a whole); the score is indicative, not a certification.
  National requirements are not shipped: the organisation adds them as its own standard.
- End of life: endoflife.date has no data for Cisco classic IOS, NX-OS or Sophos Firewall OS (they are
  defined as the organisation's own products); the edition of a Windows client (Enterprise, IoT, LTSC)
  is guessed from its name; the online update needs HTTPS to endoflife.date (a file import works
  without it).
- TLS certificates: services that switch to TLS with STARTTLS (SMTP 25/587, LDAP 389, RDP) are not
  checked; revocation (CRL/OCSP) is not checked; the name is checked only when a host name is known
  (asset host name or the service's server name).
- Global search: remediation finding titles are stored in English, so a Persian word does not find them
  (CVE ids, check numbers and asset names do); results are plain substring matches, not ranked by
  relevance beyond exact and prefix matches first.
- API keys: a key sees what a user with the same permissions sees, including ownership rules (a
  non-administrator sees only the audit sessions it started); reads made with a key are not written to the
  audit trail one by one (its last use and address are kept on the key); behind a reverse proxy the
  address list sees the proxy's address.

## On the customer side

- Test the current `main` on the test server (172.16.120.85) and report bugs.
- Delete the "NGCorion 2.0.0 appliance" draft release (deleting releases is not allowed from the
  development session).
- After testing: publish a release. The 2.1.0 draft predates items 6, 7 and 8; a 2.2.0 tagged from the
  tested `main` is the better candidate.
- Online licensing: port 443 for lic.ngcorion.com behind the WAF (offline licenses work meanwhile).

## Done (newest first)

| Item | Commit |
|---|---|
| Delivery policy for email and SMS, password reset code by SMS, sms.ir, time zone search | (this commit) |
| Version 2.1.2 | 6811f28 |
| Training and product documents brought up to date; overview and training course as PDF | c84e744 |
| Review of code annotations: references to deleted files, a wrong password rule, health route, unused lint suppressions, release examples | 17a34bc |
| Security review (OWASP WSTG): peer account takeover through its email, asset data without the Asset List permission, request body limit, error text in license activation, imported links | f95e62b |
| Two assets may share an IP: saved with a warning | e75dba6 |
| Restore preview names the device's refusal | 5e1ae2c |
| Version 2.1.1 | 4968377 |
| Review of every page and API call; fixes found by it | 7a971f1 |
| New Backup: every asset listed, device type detected from the asset; dialogs styled on their own | 75f55f0 |
| Architecture Validation: the topology against Cisco SAFE only (segmentation, edge, management, availability, visibility), with evidence; zone place in the network | 2c11d53 |
| One list of network zones: an asset's zone the same in Asset List, Risk, groups, alerts and reports; zone exposure score in Asset Requirements | 861c9b3 |
| SNMP address of a host; other addresses of an asset for syslog; assign an unknown sender | d87a0c1 |
| NOC: SNMP metrics retention and space in the app; usage of syslog and metrics against their limits | 4fe23da |
| Fix: syslog and NOC metrics storage budgets measure the stored rows, not the files | ca1fe8a |
| Assets: physical or virtual asset types; a virtual asset names its physical server | f2f7064 |
| Fix: assets save with empty serial, value and dates; last audit and last hardening dates kept automatically | b2394fc |
| Fix: risk detail Audit Findings shows hardening and verification status | ba63175 |
| Risk detail: Hardening Impact before/now (failed controls, audit risk, risk score) | b45ebff |
| Fix: Linux/Windows/SQL Server/Apache/MongoDB/benchmark hardening recorded; risk counts fixes already PASS | 5979e48 |
| Fix: OSV.dev HTTP 403 (refused by country) names a proxy, a mirror or an import | 4169673 |
| Fix: Linux SSH on systemd 257+ (OSC 3008 prompt marks) failed every command with "Pattern not detected" | 47a3603 |
| Fix: "Collect now" names a missing answer (timeout, server unreachable, 5xx without a message); a database error keeps its reason | 2133442 |
| Fix: Software "Collect now" says why it failed (WinRM login, WinRM not answering, after sign-in) | 36dfa01, 8f09502 |
| Fix: every page shows a refused request's own message (16 slices) | 6df50a8 |
| Fix: new scheduled discovery turned the page white; error boundary for every page | c279c0d |
| Fix: CVE update failed with DataError (NUL characters, long CPE criteria) | 192823c |
| Hardening overview rebuilt (needs attention, missing controls, impact in risk terms, reach) | 020f70c |
| Risk overview rebuilt (factor shares, zone by level, trend, incomplete scores, filtered risk list) | 1cab41f |
| Assets overview rebuilt (missing details, coverage, mix, filtered asset list) | de30dcb |
| Dashboard rebuilt (needs action, coverage, 90-day trends, top 10 with main factor) | 018d38a |
| In-app help (every menu page, fa and en; search inside it and from the global search) | 20c931a |
| 12 API keys (service account per key, scopes, expiry, address list, renew, revoke, expiry alert) | c7b6549 |
| 11 Global search (assets, IP, MAC, CVE, devices, findings, certificates, software, groups, users, reports, pages) | d90ec0f |
| 14 TLS certificates (scan, trust, expiry, weak key/signature, TLS 1.0/1.1, own CAs, remediation, risk, alerts, report) | d3edee3 |
| 10 End of life (catalog from endoflife.date, own products, remediation, risk, alerts, report) | fe425bd |
| Production image start: no plain methods on Pydantic models (guard test) | 6d7b258 |
| 15 Compliance with standards (PCI DSS, ISO 27001, NIST, own standards, report) | b262320 |
| 9 Benchmark policy (optional / excluded checks, four eyes, rescoring) | cfa38c5 |
| I1–I3 Bidi isolation, real ports on the map, Cisco per-VLAN MAC tables | 3ac5ec3, f0f10f8, 6ed4f95 |
| 8 Topology from LLDP and CDP | d91a854 |
| 6 Unknown devices (ARP / MAC tables), nine new icons | 2abccc5 |
| Version 2.1.0 | 9796218 |
| 7 NOC device health | 7ea62c9 |
| 13 Syslog, backup after a reported configuration change | (2.1.0) |
| 5 Asset 360 | (2.1.0) |
| 4 Scheduled configuration backups, diff, change alert | (2.1.0) |
| 1 Asset groups, tags, credential profiles, group audits, bulk edit | (2.1.0) |
| 3 Active Directory / LDAP sign-in | (2.1.0) |
| 2 Two-step sign-in (TOTP) | (2.1.0) |
