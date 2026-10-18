# Users

User accounts, roles and per-module permissions. Each user has one **role** and, for each module, three separate permissions: "Read", "Write" and "Delete". The [API keys](/settings/api-keys) tab is for other systems.

## Roles

| Role | For |
|---|---|
| System administrator (admin) | The administrators of NGCorion; access to everything |
| Manager | Security team leads; approve risk acceptances and benchmark policy, restore device configurations |
| User | Audit and hardening staff, with the permissions they need |
| Guest | Viewers (e.g. an outside auditor); read only |

## Create an account

1. "+ Add User".
2. User name, email, mobile number (for SMS alerts), **role** and a temporary password.
3. For roles other than system administrator, set "Read", "Write" and "Delete" for each module. "Use credential profiles" is needed for group audits and scheduled backups.
4. "Create". The user must change the temporary password at first sign-in.

## Other tasks (each row's buttons)

- **Edit:** role, permissions, email, mobile and status.
- **"Set a temporary password"** (system administrators only): for someone who forgot their password and has no email; all their sessions are closed.
- **"Reset two-step sign-in"** (system administrators only): when both the phone and the recovery codes are lost. **Verify the requester's identity separately first.**
- **Deactivate:** for someone leaving the organisation; their sessions close at once and their records keep their name. Delete only accounts created by mistake.

The "Two-step sign-in" column shows each user's state: on, off, due by …, or required and not set up. Directory accounts carry an AD badge; their role and password come from the domain.

## Rules the system enforces

- Someone who is not a system administrator cannot create an account with a higher role or grant a permission they lack.
- Nobody changes their own role or permissions, or deactivates or deletes themselves.
- The last active system administrator cannot be deleted or deactivated.

## Take care

> Least privilege: only what each person's work needs. Do not grant "Delete" unless needed. An outside auditor gets the guest role, and only for the audit. At least every three months, match the account list against the staff list.

## Read more

- Admin guide, section 7 · Training course, lessons 2.5 and 18.5
