# Remediation

Every open finding from five sources (audit, CVE, architecture validation, end of life and TLS certificates) is an item here, with an **owner** and a **deadline** by severity. An item closes on its own once the next audit or scan confirms the fix.

## Deadlines

| Severity | Default deadline | Longest risk acceptance |
|---|---|---|
| Exploited in the wild (KEV) | 7 days | 30 days |
| Critical | 15 days | 30 days |
| High | 30 days | 90 days |
| Medium | 90 days | 180 days |
| Low | 180 days | 365 days |

A system administrator changes these in "System Configuration → Remediation deadlines".

## An item's life

1. Open the item.
2. Set the **owner** (by default the asset's owner). Change the deadline if needed, or "use the standard deadline".
3. The owner: **"Start work"** and "Add note" (e.g. the change request number).
4. After the fix: **"Mark fixed"**. The status becomes "Awaiting verification".
5. The next audit or scan sees the fix and the item becomes **"Fixed and verified"**. If it does not, the item opens again.

## Views

| View | What |
|---|---|
| Open | Every active item |
| Overdue | Past their deadline; review weekly |
| In progress / Awaiting verification | The stage of the work |
| Unassigned | Without an owner |
| Assigned to me | Yours |
| Risk accepted | With an active risk acceptance |

## Request a risk acceptance

When a fix is not possible yet: the item → "Request risk acceptance" → scope ("This finding only", or this check/CVE on every asset) → **justification** → **compensating control** → end date → "Send for approval". A manager or system administrator other than you approves; a critical or KEV finding only a system administrator. Details on [Accepted risks](/remediation/acceptances).

## Example

CVE-2024-21762 on `fw-edge` (7-day deadline): assign it to the network owner → "Start work" with the note "upgrade window Thursday 22:00" → after the upgrade "Mark fixed" → the next audit makes it "Fixed and verified".

## Take care

> "Mark fixed" does not close the item; only the next audit or scan does. The "Remediation overdue" alert tells its recipients about late items. Finding titles are stored in English; to search, use the product's English name or the CVE id.

## Read more

- [Accepted risks](/remediation/acceptances) · [Benchmark policy](/remediation/policy)
- User guide, section 12 · Training course, lesson 11
