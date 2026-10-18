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
| I3 | Cisco IOS MAC tables of every VLAN: read the VLAN list (CISCO-VTP-MIB) and each VLAN's BRIDGE-MIB table (`community@VLAN` on v2c, context `vlan-<id>` on v3) | done |

Bugs reported from testing on the customer test server go before everything else here.

## Next: phase D (agreed order)

| Order | # | Item | Scope |
|---|---|---|---|
| 1 | 9 | Organisation policy on benchmarks | Mark CIS checks required / optional / excepted (with reason and approval); audit score and reports follow the policy |
| 2 | 15 | Compliance standards | Map checks to PCI DSS, ISO 27001, NIST and national requirements; compliance percentage, gaps, report |
| 3 | 10 | End of life | OS and firmware out of (or near the end of) vendor support; alert and risk factor |
| 4 | 14 | TLS certificates | Certificates of services and devices: expiry, weak algorithm or chain; alert before expiry |
| 5 | 11 | Global search | One search box on every page: assets, IP, MAC, CVE, findings, users, reports |
| 6 | 12 | API keys | Keys for other systems (SIEM, CMDB, scripts): scoped permissions, expiry, audit trail |

## Known limits (shipped, documented, not yet improved)

- Unknown devices: per-VLAN MAC tables on Cisco IOS are read for up to 64 VLANs per switch; on SNMP v3
  the switch must give the user the `vlan-<id>` contexts.
- Topology: an asset not polled over SNMP (or with more than 96 physical ports) still draws the generic
  port catalog of its type; a link to it is anchored on the catalog port with the same number.
- Unknown devices / topology: tested against snmpsim and net-snmp agents, not yet on real switches.

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
