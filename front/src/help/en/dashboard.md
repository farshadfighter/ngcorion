# Dashboard

The organisation's security at a glance: the overall risk score, the number of assets, assets at critical risk and exposed to the internet, the compliance score and the hardening score. Start each working day here and follow the cards to the detail pages.

## What the cards say

| Card | Meaning |
|---|---|
| Security risk score | Average risk of the assets from 0 to 100; higher is worse |
| Total assets | Assets that have a risk score |
| Critical risk assets | Assets scoring 60 or more |
| Internet exposed assets | Assets in the Internet/public or DMZ zone |
| Compliance score | Share of passed controls in each asset's latest audit |
| Hardening score | Share of hardening actions that succeeded and were verified |

## Risk scale

| Score | Level |
|---|---|
| 0 to 9 | Minimal |
| 10 to 24 | Low |
| 25 to 39 | Moderate |
| 40 to 59 | High |
| 60 to 100 | Critical |

"Some inputs are incomplete, so this score is provisional." under the gauge means some assets have not been audited yet or their details are incomplete.

## A suggested daily routine

1. Look at the risk score and "Assets Requiring Attention".
2. From "Top 20 Risky Assets", open the worst asset and see which factor raised its score.
3. Go on to [Alerts](/alerts) and [Remediation](/remediation).

## Take care

> The total here comes from the risk scores; a new asset that has not been scored yet is not counted. The full list is the [Asset list](/assets/inventory).

## Read more

- [Risk overview](/risk/overview) · [Risk of assets](/risk/assets)
- User guide, section 5 · Training course, lesson 10
