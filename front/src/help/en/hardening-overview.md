# Hardening overview

How hardening is going and what needs a person, in five parts: the figures, what needs attention, the controls still missing, what hardening changed in risk terms, and how far it reaches. Only changes that ran count; previews do not.

## Figures

| Figure | Meaning |
|---|---|
| Success rate | Changes that succeeded, of those that succeeded or failed |
| Changes made | Changes that ran (succeeded or failed) |
| Changes in the last 30 days | Changes started in that time |
| Assets hardened / Assets never hardened | Assets with at least one successful change, and the rest |
| Failed, not fixed since | Failed changes no later successful change on the same asset and control made good |
| Pending Actions | Changes waiting or running |

## Needs attention

| List | What to do |
|---|---|
| Failed changes | Read the error from the device. If the device misbehaves, "Restore the backup from before the change" opens its backups; then "Try again" opens the hardening of failed controls. |
| Not verified or not holding | "Check still fails": the change ran but the control still fails. "Not verified": nothing checked the device afterwards. Audit the device again. |
| Hardened since the last audit | Their compliance and risk still show the old findings; "Run audits" brings them up to date. |

A list with nothing in it says "Nothing here.".

## Missing controls and impact

**Top Missing Hardening Controls** lists the controls failing in each asset's latest audit that no change has fixed, by the number of assets. "Affected assets" opens [Remediation](/remediation) searched for that control; "Fix with hardening" opens the hardening of failed controls.

**Hardening Impact** shows the findings hardening fixed (critical and high apart), and the average risk of the assets hardened in the last 90 days just before their first change and now.

> "Risk now" includes everything else that happened to those assets since (new CVEs, new open ports), so it can rise even when hardening worked.

## Reach

Assets with a successful change per asset type (a row opens that type in the asset list), the success rate per benchmark level, and the latest changes with their result.

## What to do from here

1. Clear **Failed changes** first: a half-applied change can leave a device in an unknown state.
2. Audit what is in **Hardened since the last audit** so the scores are real.
3. Plan the next hardening from **Top Missing Hardening Controls**: one change fixes it on every asset.

## Read more

- [Run hardening](/hardening) · [Remediation](/remediation) · [Backups](/backup)
- User guide, section 8 · Training course, lesson 6
