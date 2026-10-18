# Architecture validation

Checks the asset inventory, the topology and the audit results against secure-architecture rules, and finds structural weaknesses: a critical asset without redundancy, assets without an owner or IP, a vital device without a configuration backup, a high-risk asset not audited for a long time, and so on.

## Example rules

| Rule | Severity | Category |
|---|---|---|
| Critical asset lacks redundancy | High | Topology |
| Critical asset has no configuration backup | High | Resilience |
| High-risk asset is active without a recent audit | High | Compliance |
| Asset has no redundant link | Medium | Topology |
| Asset has never been audited / last audit failed | Medium | Compliance |
| Asset has no IP address | Medium | Inventory |
| No owner / confidentiality level not classified | Low | Inventory |

## Main tasks

1. "Run Analysis" runs every rule on the current state.
2. Read the "Open" findings; each has a recommendation.
3. For each finding, one of:
    - **Fix:** correct the problem (e.g. set an owner) and analyse again; the finding disappears.
    - **"Accept":** you knowingly accept the risk; it moves to "Accepted".
    - **"Ignore":** it does not apply to you; with a reason.

Open findings also go to [Remediation](/remediation).

## Example

"Critical asset lacks redundancy" for `fw-edge`: you have a single edge firewall. If a second one is planned this year, "Accept" it with that explanation until then; otherwise keep it as a remediation item with a deadline.

## Take care

> The topology rules need a complete map; with an incomplete [Topology](/topology) you will see many "no links" findings. Set up LLDP/CDP first.

## Read more

- [Suggested design](/design-suggestion) · User guide, section 16
