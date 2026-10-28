# Run audits

Compares an asset's configuration with its reference benchmark (CIS, DISA STIG or the vendor's guide). An audit **only reads** and changes nothing on the device. The list on this page is the audits you ran.

## Run an audit

1. "Add New Auditing".
2. **Job name** and **asset**; the device type is suggested from the asset.
3. **Credentials**, by target:

    | Target | Credentials |
    |---|---|
    | Linux, Apache, NGINX, Docker, Kubernetes | SSH user name and password, port, "Sudo Password" |
    | Cisco | SSH user name and password, and the enable password |
    | FortiGate | SSH user name and password; "Detect VDOMs" and pick one VDOM or "All VDOMs" |
    | Windows and its roles | `Administrator` or `DOMAIN\user`, password, WinRM port and "Transport" |
    | SQL Server, MySQL, MongoDB | An account of that database |
    | Sophos Firewall | An administrator with API access and the API port |
    | ESXi | root or an account with the Administrator role; SSH on during the audit |

4. Set any option offered (e.g. "Server Role": "Domain Controller" or "Member Server").
5. "Next" and run. An audit takes a few minutes.

## Read the result

- "See Result" shows the compliance score and the "Conformity" and "Non-Conformity" counts. Both are over the scored checks, so they add up to 100% and the conformity is the score in reports and dashboards; not applicable checks, errors, informational checks and checks the benchmark policy makes optional or excludes are counted apart, as "not scored".
- Each control: section, severity, result and "Evidence / Remediation" (what was read from the device and how to fix it).
- **"⚠ Manual review":** a heuristic or manual control; confirm it yourself.
- "Report of this audit, with the evidence of every check": a PDF for the auditor.
- From the result, go to [Hardening](/hardening) to fix the failed controls.

## Example

`web-01` (Ubuntu): user `ngc-audit`, port `22`, sudo password. Result: 62%; a failed control `5.2.10` with evidence `PermitRootLogin: yes` and the advice `Set PermitRootLogin no in /etc/ssh/sshd_config`.

## Credentials and security

- Credentials are used for this run only and are not stored.
- On the first connection, the device's SSH key (or the Sophos HTTPS certificate) is pinned. If it later changes, the connection is refused **before any password is sent**; do not retry, tell a system administrator.
- For regular audits, prefer a [group audit](/audit/group-runs) with a credential profile.

## Common problems

| Situation | Cause and fix |
|---|---|
| The audit failed | Address, port, user name, password, or a firewall in between |
| Many controls show an error | No sudo password, or the account cannot read the files |
| WinRM does not connect | WinRM is off on the server, or the transport is wrong |
| The host key changed | The device was reinstalled or is being impersonated; tell an administrator |

## Take care

> Deleting an audit or "Clear History" cannot be undone, but the audit-trail record ("who audited what, when") stays. Users other than system administrators see only their own audits.

## Read more

- [Group audits](/audit/group-runs) · [Audit schedules](/audit/schedule-auditing)
- User guide, section 7 · Training course, lesson 4
