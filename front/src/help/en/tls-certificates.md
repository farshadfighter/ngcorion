# TLS certificates

The certificates of the assets' TLS services: websites, firewall and switch management, ESXi, LDAPS, mail and so on. NGCorion does only a TLS handshake: no password is needed and nothing changes on the device. This is not about NGCorion's own certificate.

## What is checked

| Problem | Finding severity |
|---|---|
| Expired | High |
| Expiring (within 30 days by default) | Alert only |
| Untrusted: self-signed or unknown issuer | Medium |
| Weak key (RSA under 2048 bits) or weak signature (SHA-1, MD5) | Medium |
| TLS 1.0 or 1.1 accepted | Medium |
| Wrong name: the certificate does not name the asset's host | Low |

## Main tasks

- **"Scan now":** the scan runs every 24 hours on its own; this reads everything right away.
- **One service's details:** click the row for the certificate, chain, fingerprint and the explanation of each problem; "Scan this asset again" after a renewal.
- **"Add a service":** for a port not in the list, or a site on a shared server with its own name: the asset, the port and, if needed, the server name (SNI).
- **"Turn off":** a service that is not the organisation's is no longer scanned.

Views: "Needs attention", "All", "No answer" (services that did not answer in the last scan) and "Settings".

## Example

| Service | Problem | Action |
|---|---|---|
| `esx-01:443` | Self-signed | Issue and install a certificate from the organisation's CA |
| `web-01:443` | Expiring (12 days) | Renew, then "Scan this asset again" |
| `dc-01:636` | Unknown issuer | A system administrator adds the internal CA certificate to the trusted issuers under "Settings" |

After the fix, the remediation finding closes on its own.

## Settings (system administrators only)

The ports checked, the scan interval (6 to 168 hours), the warning days before expiry (7 to 180), the TLS 1.0/1.1 check, and the organisation's **trusted issuers** (a PEM certificate only, never a key).

## Take care

> Services that start encryption with STARTTLS (SMTP on 25 and 587, LDAP on 389) are not checked, and neither is revocation (CRL/OCSP). NGCorion must be able to reach these ports from its own network.

## Read more

- [Vulnerabilities (CVE)](/cve)
- User guide, section 10.1 · Admin guide, section 5.12 · Training course, lesson 9.2
