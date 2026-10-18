# Risk overview

The big picture of asset risk: how many assets are at critical, high or medium risk, the average score, the assets with incomplete data, and the spread by risk level, zone and confidentiality level.

## How the risk score is built

Every asset has a score from 0 to 100 (higher is worse), made from these factors:

| Factor | Source | Default weight |
|---|---|---|
| Asset importance | Risk profile and confidentiality level | 20% |
| Inherent asset risk | The recorded risk level | 15% |
| Network zone | Risk zones (e.g. DMZ, internal) | 15% |
| Open ports | Network discovery or entered by hand | 10% |
| Audit failures | Weighted share of failed controls in the latest audit | 20% |
| Identified remediation | Failed controls with a known fix | 5% |
| Known vulnerabilities | The worst of CVE, end of life and TLS certificate | 15% |

## Cards

| Card | Meaning |
|---|---|
| Number of incomplete assets | Assets missing data for the calculation (e.g. not audited yet) |
| Non-conformity asset | Assets with active audit findings |
| Number of fixed section by hardening | Controls hardening has fixed |

## Where to go from here

- See the critical assets in [Risk of assets](/risk/assets), sorted by score, and open each one's factors.
- Audit the **incomplete assets**; until then their score is not real.

## Take care

> A finding whose risk is formally accepted is left out until the acceptance ends, and so is a control the benchmark policy excludes. A low score sometimes comes from exceptions, not fixes.

## Read more

- User guide, section 11 · Training course, lesson 10
