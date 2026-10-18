# Group audits

Audits every asset of a group in one job, signing in with a **credential profile** a system administrator made (you never see its password). Each asset gets its own regular audit; assets that could not be audited are listed with the reason and can be tried again.

## Start a group audit

1. "Start a group audit".
2. **Asset group**, **technology** and **benchmark profile** ("Level 1" or "Full (Level 1 and 2)").
3. **Credential profile** of the matching kind (SSH, WinRM, SQL Server or Sophos API).
4. **Assets audited at the same time:** 1 to 50.
5. "Start".

## Read the result

Each run's row shows its progress; open it for each asset's result:

| Result | Meaning and fix |
|---|---|
| Audited | Go to its session from the "Compliance" column |
| Sign-in refused | The account or sudo password is missing or different on that device |
| Unreachable | A firewall, the device is off, or another port |
| Skipped (license or no address) | Outside the license limit, or the asset has no IP |
| Error | Read the details |

- **"Retry n failed":** audits only those again.
- **"Stop":** cancels the assets not started yet; running audits finish.
- If any asset failed at the end, the alert "Group audit finished with failures" is raised.

## Example

Group "Linux servers", technology Linux, level 1, profile `linux-audit`, 10 at a time. Two servers fail with "Sign-in refused" because the `ngc-audit` account was never created on them; after creating it, "Retry 2 failed".

## Who can?

Audit "write" permission plus the permission to use credential profiles. If no profile of the needed kind exists, ask a system administrator to make one. A warning shows next to a profile whose password is older than its change period.

## Read more

- [Asset groups](/assets/groups) · [Audit schedules](/audit/schedule-auditing)
- User guide, section 7.5.1 · Training course, lesson 5.1
