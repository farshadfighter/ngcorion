# Software

Two tabs. **"Installed Software"** lists the packages, programs, services and firmware of the assets, read during audits. **"End of life"** shows until when the vendor ships security fixes for each asset's OS, firmware and server software.

## Installed software

- **Filters:** "Outside the distribution repository" (installed outside the official repository; more risk), "With vulnerabilities", "Several versions" (one product in several versions), "Unidentified" (a product without a CPE, so its CVEs cannot be matched).
- **"Collect now…":** reads only one asset's software list, without a full audit; e.g. after installing a patch.
- **"Identify…":** give an unidentified product its CPE so its vulnerabilities are found.
- **"Export to Excel":** this list with the same filter.

## End of life

| Status | Meaning | Remediation finding |
|---|---|---|
| Unsupported | The vendor's security-fix date has passed | High |
| Paid extended support only | E.g. Ubuntu ESM or Windows ESU | Medium |
| Support ends within N days | 180 days by default | — |
| Supported | — | — |
| Not in the catalog | endoflife.date does not track it | — |

Views: "Needs attention", "All", "Not in the catalog" and "Catalog". Click a product name to open its assets.

## Manual entries and your own products

- **"Enter an end of support":** for a device without a software list (camera, controller, old switch): the asset, name, version, the end of security fixes, and the source of the date in the note.
- **Your own product** (manager or system administrator): for software endoflife.date does not cover (e.g. Sophos Firewall OS or classic Cisco IOS), in the "Catalog" view or with "Add as a product". A version matches a cycle by its first numbers: `20.0.1` means cycle `20.0` or `20`.

## Example

`web-02` runs Ubuntu 20.04: standard support has ended and only paid ESM remains, so "Paid extended support only" and a medium finding in Remediation. After the upgrade to 22.04 or 24.04 and a new audit, the finding closes on its own.

## Take care

> The software list is built by Linux or Windows audits. An asset not audited yet has neither CVEs nor end-of-life results; "no finding" then means "no data", not "safe".

## Read more

- [Vulnerabilities (CVE)](/cve)
- User guide, sections 6.4 and 6.5 · Training course, lesson 9.1
