# Risk overview

How much risk there is, what builds it, where it sits and where it is heading: assets per risk level, what each factor adds to the scores, assets per zone and level, the 90-day trend, scores that lean on defaults, and the ten riskiest assets. Every figure, factor and cell opens [Risk of assets](/risk/assets) filtered to what it counts, or the page where that factor is fixed.

## How the risk score is built

Every asset has a score from 0 to 100 (higher is worse), made from these factors:

| Factor | Source | Default weight |
|---|---|---|
| Criticality | Risk profile and confidentiality level | 20% |
| Asset Risk | The recorded risk level of the asset | 15% |
| Zone | Risk zones (e.g. DMZ, internal) | 15% |
| Open Ports | Network discovery or entered by hand | 10% |
| Audit Risk | Weighted share of failed controls in the latest audit | 20% |
| Hardening | Failed controls with a known fix | 5% |
| Vulnerability | The worst of CVE, end of life and TLS certificate | 15% |

## What the page shows

| Part | Meaning |
|---|---|
| Figures | Scored assets, the average score, assets at critical, high and medium risk, incomplete data, and assets with exploited vulnerabilities (KEV) |
| What builds the risk | Average points each factor adds to an asset's score and its share of the average score; click a factor to open where it is fixed |
| Zone by risk level | Assets in each zone at each level; a number opens the list of exactly those assets |
| Last 90 days | The average score, and the critical and high assets, one point every 5 days from each asset's latest score at that moment |
| Incomplete scores | Why scores lean on defaults (never audited, no port scan, no zone or criticality chosen) with the action that fixes each, and the first such assets |
| Top 10 risky assets | The riskiest assets with the factor that adds most to each score |

## Filtered lists

Risk of assets shows the filter as a chip above the table ("Risk level: High", "Zone: DMZ", "Incomplete data"); click the chip to remove it. The filters work in the address too:

```
/risk/assets?level=critical
/risk/assets?zone=3&level=high
/risk/assets?incomplete=1
```

## Where to go from here

- Start from the biggest factor in "What builds the risk": for Vulnerability go to the CVE findings, for Audit Risk to the failed controls.
- Clear "Incomplete scores": until then those scores are not real.
- A zone with many critical or high assets is where segmentation or a firewall rule review pays off first.

## Take care

> A finding whose risk is formally accepted is left out until the acceptance ends, and so is a control the benchmark policy excludes. A low score sometimes comes from exceptions, not fixes.

## Read more

- [Risk of assets](/risk/assets) · [Dashboard](/overview)
- User guide, section 11 · Training course, lesson 10
