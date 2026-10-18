# Benchmark policy

Here the organisation decides which controls of the audit benchmarks (CIS, STIG …) it **does not need**. Unlike a risk acceptance, which is about one finding on one asset, a policy is about **the control itself**: it applies to every past and future audit of that benchmark. Every rule takes effect only after someone else approves it.

## Add a rule

1. Click "New rule".
2. Pick the **benchmark** (e.g. Linux).
3. **Applies to:** "One check" (each shows whether it failed in the latest audits) or "A whole level" (e.g. L2).
4. **Assets:** "Every asset" or one asset group.
5. **Decision:** "Optional" or "Excluded" (next section).
6. Write the **reason**; an end date is optional but recommended (e.g. one year).
7. "Ask for approval". The request waits under "Waiting for a decision" until someone else approves it.

## Example

Linux control `1.1.5` (a separate partition for `/var/log`) is not needed on the organisation's virtual machines, because a full disk is caught by a NOC alert:

- Benchmark: Linux · Control: `1.1.5` · Scope: group "Linux servers"
- Decision: **Optional** · End date: in one year
- Reason: "A full disk is watched by the NOC alert "Disk almost full"."

The auditor submits the request and the security team lead approves it.

## Optional or excluded?

| Decision | Meaning | Compliance score | Remediation | Risk score |
|---|---|---|---|---|
| Optional | Recommended, not required | Not counted | Closed | Kept |
| Excluded | Does not apply here | Not counted | Closed | Removed |

The control's result still shows in the audit; it only stops counting in the scores.

## What happens after approval?

- Every audit of that benchmark is **scored again**, and later audits are scored with the rule too.
- Remediation items of the control close with the reason "The benchmark policy does not require this check".
- The score without the policy is kept: the "Benchmarks" tab shows both side by side.
- A rule whose end date passes expires on its own and the controls count again.

## Tabs

| Tab | What |
|---|---|
| In force | Approved rules; "End the rule" stops one |
| Waiting for a decision | Requests not yet approved or rejected |
| Ended | Rejected, cancelled and expired |
| Benchmarks | Average score with and without the policy, and the number of optional and excluded results |

## Who does what?

| Action | Who |
|---|---|
| View | Audit "read" permission |
| Request | Audit "write" permission |
| Approve or reject | Manager or system administrator, **never the requester** |
| Approve a whole level, or excluding a high/critical control | System administrator only |
| Cancel a pending request | The requester or a system administrator |

## Take care

> Excluding a control also removes it from the risk score. Choose "Excluded" only when the control truly does not apply; if it is merely a low priority, "Optional" is right.

- Prefer a group scope: a rule on "All assets" also covers assets added later.
- Write the reason so an outside auditor understands it; all of this is recorded in the audit trail.

## Common problems

| Situation | Cause |
|---|---|
| No "Approve" button | The request is your own, or your role is not manager or system administrator. |
| Approval refused | The rule covers a whole level or excludes a high-severity control: only a system administrator may approve it. |
| The score did not change | The rule is still awaiting a decision, or its scope does not include those assets. |

## Read more

- [Accepting the risk of one finding](/remediation/acceptances)
- [Compliance with standards](/compliance) (follows the same policy)
- User guide, section 12.1 · Training course, lesson 11.4
