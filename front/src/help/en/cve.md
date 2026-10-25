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

## Recommended action

Every finding (in the CVE detail, [Remediation](/remediation), the asset page and the report) has a "Recommended action":

| Case | Action |
|---|---|
| Linux package | "Upgrade age to … or later", with the commands (`apt-get`/`dnf`) to copy and the advisory (USN, DSA, RHSA). A fix only in Ubuntu Pro (ESM) says so, and the commands start with `pro attach` |
| Linux kernel installed but not running | "Restart the machine" |
| Windows | "Install the latest cumulative update (build … or later)", with the CVE's page in Microsoft's Security Update Guide, which names the KB |
| Devices and other software | "Upgrade FortiOS to 7.2.9 or later": the fix in **the branch installed**, from NVD's ranges; marked "check it against the vendor's advisory", with the vendor's advisory (FortiGuard, Cisco, VMware/Broadcom, Sophos, …) |
| No fixed version known (e.g. Cisco) | "Follow the vendor's advisory", with that advisory |

CISA's required action and due date for KEV CVEs, and an operating system or firmware past its end of life (no more fixes), are said next to the action.

**Upgrade plan:** on the asset page ("What to do first") and in the "Upgrade plan" section of the CVE report, each asset's actions with the findings each closes, e.g. "Upgrade FortiOS to 7.2.9 closes 12 findings". CVE alert emails carry the first steps too.

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
| Advisories update: "OSV.dev refused the download (HTTP 403)" | Google, which hosts OSV.dev, refuses addresses in some countries. A system administrator sets a proxy (`HTTPS_PROXY`) or a mirror (`OSV_BASE_URL`) in `.env`, or downloads `all.zip` on another network and imports it. |

## Read more

- [TLS certificates](/cve/certificates) · [Software](/assets/software)
- User guide, section 10 · Training course, lesson 8
