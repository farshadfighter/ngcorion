# Run hardening

**Applies secure settings on the device**, with a command preview, a backup before the change and verification after it. Run it only with the organisation's change approval (e.g. an approved change request).

## Two ways

| Option | When |
|---|---|
| Fix all section | An asset not audited yet: first an audit, then hardening of every CIS benchmark section |
| Fix Unsuccessful section | An audited asset: the failed controls of that audit (the usual way) |

## Steps (Fix Unsuccessful section)

1. "Fix Unsuccessful section" → "Next" → the asset's audit session.
2. **Review:** tick the controls to fix. Controls with no automatic fix (e.g. settings only possible through GPO) are left out.
3. **Parameters:** give a value to controls that "Needs parameters" (password length, syslog server address …). A blank optional field means the CIS default.
4. **Credentials:** used for this run only, never stored.
5. Keep **"Back up the device configuration first"** on.
6. **"Preview Commands":** the exact commands, without connecting or changing anything. Read them.
7. **"Apply Hardening"**.

## Result

| Result | Meaning |
|---|---|
| Fixed | The commands ran without error **and** verification confirmed the change |
| Failed | A command failed or verification did not see the change; read the output |
| Skipped | Could not be fixed automatically, or was not selected |

After hardening, **audit the asset again**.

## Example

`fw-edge`, the control locking the admin account after failed sign-ins. Parameters: threshold `3` and duration `60` seconds. Preview:

```
config system global
 set admin-lockout-threshold 3
 set admin-lockout-duration 60
end
```

## Take care

> Some settings (restricting SSH, sign-in policies) can cut your or NGCorion's access. Read the preview with that in mind and keep another way in (a console). On vital devices, run controls one at a time or in small groups, not "Harden All Failed Checks". For ESXi, the SSH service must be on during the run.

## Common problems

| Situation | Fix |
|---|---|
| Everything "Failed" | Check the credentials or the sudo/enable access |
| SSH access lost after the fix | Sign in from a console; if you took a backup, restore it from [Device Backups](/backup) |
| The next audit still shows a failure | Read the command output; some changes need a service restart |

## Read more

- [Hardening overview](/hardening/overview) · [Device Backups](/backup)
- User guide, section 8 · Training course, lesson 6
