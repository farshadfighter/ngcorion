# Risk of assets

The assets sorted by risk score, worst first. Click one to open its risk page: score and level, factors, audit findings, open ports, hardening impact and risk history.

## Read one asset's risk page

1. **Risk score and level**, with the "Data Completeness Status". "Incomplete" means the score is provisional.
2. **Criticality, confidentiality and zone:** they come from the Asset list.
3. **Audit findings:** failed controls with severity, actual value and hardening status.
4. **Open ports:** with each port's severity and whether it counts in the risk.
5. **Hardening impact:** since the last audit: failed controls and audit risk just after the audit and now, and the risk score before the first change and now. Cisco and FortiGate fixes count as failed until the next audit; the card says how many. The risk score also moves with everything else that changed since (new CVEs, open ports).
6. **Risk history:** every recalculation and its trigger (audit, hardening, zone change, risk acceptance …).

## Change the zone or criticality

"Edit Zone" or "Edit Criticality" → the new value → a **reason** → "Save & recalculate". Every change is kept in the risk history with its reason.

## Example

`pay-app` scores 64 (critical). Its factors show most of it comes from a CVE in KEV and 35% failed controls. So, in order: close the CVE, harden the high-severity controls, and close port `8080` if it is not needed. After each step, the risk history shows the score falling.

## Take care

> Criticality and zone are business facts; do not change them to lower the number. An outside auditor sees the reason for every change in the history.

## Read more

- [Risk overview](/risk/overview) · [Remediation](/remediation)
- User guide, section 11 · Training course, lesson 10.3
