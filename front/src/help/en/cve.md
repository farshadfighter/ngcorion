# Vulnerabilities (CVE)

Known vulnerabilities in the software and operating systems of the assets, from the local CVE database (NVD) and the Linux distributions' security advisories (OSV), ordered by what to fix first. Nothing about your assets is sent outside your network.

## Priority

| Priority | Condition | Meaning |
|---|---|---|
| 1 — fix now | In the CISA KEV list | Attackers are using it right now |
| 2 | CVSS 9 or more, or EPSS 50% or more | Very dangerous or very likely |
| 3 | CVSS 7 or more, or EPSS 10% or more | Important |
| 4 | The rest | In the normal update cycle |

CVSS says **how bad** a vulnerability is; KEV and the "Exploit likelihood" (EPSS) say **how likely it is to be used**.

## Views

| View | For |
|---|---|
| Fix first | Only the urgent and critical ones; start here |
| All findings | Everything, with search and a source filter |
| By update | Which update closes how many CVEs at once; plan patching here |
| By asset | Which asset has the most findings |
| By CVE | Which assets one CVE is on |

## Example

`fw-edge` runs FortiOS 7.2.5 and has **CVE-2024-21762** (an SSL VPN vulnerability), which is in KEV, so "fix now":

1. "By update" shows that upgrading to the fixed release of the same branch also closes several other CVEs.
2. An item with a 7-day deadline was created in [Remediation](/remediation); assign it to the network owner.
3. Before the upgrade, take a configuration [backup](/backup).
4. After the upgrade, audit the device again; the finding disappears and the item becomes "Fixed and verified" by itself.

## Where findings come from

- Products and versions are read from the **software list** (Linux and Windows audits) and the asset's OS.
- An asset with no recognised product matches nothing; record its products with "Add their software".
- On Linux, the distribution's advisory gives the exact fixed package version (source "Distribution advisories").

## Common problems

| Situation | Cause |
|---|---|
| "CVE database not loaded" | A system administrator must load it in the [Vulnerability database](/cve/database). |
| A finding does not close after patching | The software list is old; audit again or "Collect now" in Software. |
| An asset has no finding at all | It may not be audited yet and so has no software list. |

## Read more

- [TLS certificates](/cve/certificates) · [Software](/assets/software)
- User guide, section 10 · Training course, lesson 8
