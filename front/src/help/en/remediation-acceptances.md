# Accepted risks

Every exception: findings not being fixed for now, with reason, compensating control, approver and end date. An accepted finding does not count in the risk score until the acceptance ends; then it opens again.

## Approve or reject a request

1. The "Awaiting approval" tab.
2. Read the reason and the **compensating control**: does it really reduce the risk?
3. "Approve" (with an optional note) or "Reject" (with the reason for rejecting).

**Rules:** a manager or system administrator approves; a critical or KEV finding only a system administrator; nobody decides on their own request. The duration cannot exceed the maximum for that severity.

## Tabs

| Tab | What |
|---|---|
| Awaiting approval | Requests that need a decision |
| Active | Acceptances in force |
| Ending within 7 days | The requester is reminded 7 days before the end |
| Expired or withdrawn | Ended |
| Rejected | Rejected requests |

## A good request

| Part | Example |
|---|---|
| Finding | A high-severity CVE in a library of an old application on `db-01` |
| Reason | The vendor ships a compatible version in two months |
| Compensating control | `db-01` reachable only from `pay-app` and the management network; sign-ins watched in the SIEM |
| Scope | This finding only |
| Duration | 60 days (at most 90 for high) |

## Take care

> A risk acceptance is not a fix. Before it ends, either fix the finding or request again with a new reason. A scope "on every asset" also covers assets that get the same finding later; use it with care. For a control the organisation does not need at all, the [benchmark policy](/remediation/policy) is the right tool.

## Read more

- [Remediation](/remediation)
- User guide, section 12 · Training course, lesson 11.3
