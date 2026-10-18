# Logs and audit trail

Every security-relevant action and every sign-in attempt, kept unchanged: who, when, from where, did what, to what, with which result. Records are protected against editing and deletion by a database trigger.

## Tabs

| Tab | What |
|---|---|
| Security events | User and permission changes, audits, hardening, restores, settings, risk acceptances, keys … |
| Sign-ins | Every sign-in attempt, successful or not, with the network address |
| Module activity | The last 50 events of each module (asset management, discovery, hardening …) |

## Search and filter

Search the action, user, module or detail; filter by module, action, result, user name, address and date range. "Export CSV" gives what the filters select (at most 100,000 rows). **The export itself is recorded under your name.**

## Suggested weekly review

| What | How |
|---|---|
| Repeated failed sign-ins, or from unfamiliar addresses | "Sign-ins", result: failed |
| Role and permission changes | "Security events", module users |
| Hardening and configuration restores | Modules hardening and backup |
| A pinned device key deleted | Search `device_key.forget` |
| Local administrator signing in during a domain outage | Search `emergency_login` |

## Example

"Who hardened `fw-edge` yesterday?" → "Security events", module hardening, yesterday's dates, search `fw-edge`.

## Take care

> The export holds user names and network addresses; keep it like sensitive data. Each event's description is shown in the interface language, but the database and the CSV keep the original English text. To free space, use the command-line archive tool (Admin guide, section 8.5).

## Read more

- User guide, section 17 · Admin guide, section 8 · Training course, lesson 17.2
