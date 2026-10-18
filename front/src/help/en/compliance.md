# Compliance with standards

Shows how far the latest audits meet each standard. PCI DSS 4.0, ISO/IEC 27001:2022 and NIST SP 800-53 rev. 5 ship with the product, and the organisation can add its own (e.g. national requirements).

## Where a requirement's evidence comes from

Every audit control (from all 17 technologies) is placed, from its title, in one or more **security domains** (authentication and passwords, audit logging, encryption in transit, unneeded services …). Each requirement of a standard takes these domains, or specific controls, as evidence. Requirements no control covers (e.g. "information security policy") are assessed by hand.

## A requirement's status

| Status | Meaning |
|---|---|
| Met | No failed result in its evidence |
| Partly met | Both passed and failed results |
| Not met | No passed result |
| Not assessed | Neither audit evidence nor a manual assessment |
| Not applicable | Declared by hand, with a reason |

The standard's score is the average of its scored requirements, and "Coverage" is the share of requirements that have a status.

## Main tasks

1. Pick the **standard and scope**: "Every asset" or one group (e.g. "Card data environment").
2. **"Gaps":** the failed controls behind the requirements, high severity and most assets first. This is your [hardening](/hardening) plan.
3. **"Assess by hand":** click the requirement → met / partly / not met → a note (what shows it) → valid until (one year by default).
4. **"Report":** the "Compliance with a standard" report for this standard and group.

## Tabs

| Tab | What |
|---|---|
| Requirements | By section, with filters "With gaps", "Not assessed" and search |
| Gaps | Failed controls with their assets |
| Domains of the checks | Which domain each control is in; a system administrator corrects it |
| Standards | On/off, export of the definition file, and "Add a standard" |

## Example

PCI DSS 4.0 on the group "Card data environment": under "Gaps", the SSH and logging controls of the payment servers come first; harden them and audit again. Mark requirement `12.1` (information security policy) as met by hand with the note "Information security policy v3, approved by the board".

## Your own standard

"Add a standard" → "Start empty", then "New requirement" (number, section, Persian and English title, and domains or control numbers; all empty means assessed by hand), or "Import a file" in the "Export" format. Making and changing a standard is for managers and system administrators.

## Take care

> The score is an indicator; it does not replace a qualified assessor. Audit results cannot be changed by hand; a requirement with audit evidence can only be declared "Not applicable", with the reason. An expired manual assessment no longer counts. Controls the [benchmark policy](/remediation/policy) makes optional or excludes are not in the score.

## Read more

- User guide, section 12.2 · Training course, lessons 11.5 and 18.3
