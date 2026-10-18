# Hardening overview

The outcome of hardening: how many assets are hardened, how many actions succeeded or failed, which controls are still missing on the most assets, and the critical and high findings before and after hardening.

## Sections

| Section | What it says |
|---|---|
| Hardening Score | Share of hardening actions that succeeded and were verified |
| Hardened / Non-Hardened Assets | Assets with or without a successful hardening |
| Failed Hardening Actions | Changes that ran but were not verified or returned an error |
| Top Missing Hardening Controls | Controls still failing on the most assets |
| Assets Requiring Hardening | Assets with their risk and active findings |
| Hardening Impact | Critical and high findings before and after hardening |
| Recent Hardening Activities | The latest changes: time, asset, control and result |

## What to do from here

1. Go through the **Failed Hardening Actions** one by one: read the command output and restore from a [backup](/backup) if needed.
2. **Top Missing Hardening Controls** is the best list for the next hardening plan: one change across every asset.
3. After each hardening, audit the asset again so its real state is recorded.

## Read more

- [Run hardening](/hardening)
- User guide, section 8 · Training course, lesson 6
