# Security

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainers (not in a public
issue). Include the affected version (`/api/health` shows it), the steps to
reproduce, and the impact you observed.

## Security controls

How the product authenticates, limits and records what its users do. The same
controls are mapped to the AFTA / Common Criteria requirements in
`docs/SECURITY_TARGET.md`.

| Area | Control |
|---|---|
| Accounts | Personal accounts, roles (admin, manager, user) and per-module read/write/delete permissions, checked on every API call. |
| Passwords | Strength rules on every new password; bcrypt hashes; a password set by an admin (new account, reset) must be changed at the next sign-in; reset codes by e-mail are single-use, short-lived and rate-limited. |
| Sign-in | 5 failures from one address or 10 for one account within 15 minutes block further attempts for 15 minutes; every attempt is recorded (`login_logs`). |
| Sessions | JWT with a random id: logout revokes it at the server; a password change ends every other session; a session unused for `SESSION_IDLE_TIMEOUT_MINUTES` (30) is ended, and the UI signs out after the same time without input; a token lasts `ACCESS_TOKEN_EXPIRE_MINUTES` (120) at most. |
| Notice | A notice on the login page before sign-in (`LOGIN_BANNER`, or the built-in one). |
| Audit trail | Privileged actions are recorded in `audit_logs` (who, what, target, address, result, time). A database trigger refuses any change or deletion; only the backup/restore engine, which replaces the whole database, may. Sign-in history is not clearable from the Logs page either. |
| Device credentials | Entered per run and never stored, except for scheduled jobs, whose credentials are encrypted (Fernet) with a key outside the database; SSH host keys are pinned (trust on first use). |
| Licensing | Answers from the license server are Ed25519-signed and verified against keys built into the code; no configuration can switch this off. |
| Transport | HTTPS only (Traefik, TLS 1.2+), HSTS and security headers; the API is not reachable without TLS. |

## Dependency checks

CI checks every locked dependency against the known-vulnerability databases on
each push (`.github/workflows/ci.yml`, job *Dependencies*):

- Python: `pip-audit` over the packages pinned in `uv.lock`.
- npm: `npm audit --audit-level=moderate` over `front/package-lock.json`.

Dependabot (`.github/dependabot.yml`) opens weekly update pull requests and
immediate ones for security advisories.

### Dependency exceptions

Each exception below was reviewed; it is listed in the CI command with
`--ignore-vuln` and must be re-reviewed when the dependency changes.

| Advisory | Package | Why it is accepted | Revisit when |
|---|---|---|---|
| PYSEC-2026-2858 / CVE-2026-44405 | paramiko 4.0.0 | Paramiko 4 still *allows* SHA-1 (ssh-rsa signatures, `diffie-hellman-group14-sha1` key exchange) as a fallback. Paramiko 5 removes them, which would make older audited devices (Cisco IOS 12.x/15.0, old ESXi and appliances) unreachable. SHA-2 algorithms are negotiated first whenever the device offers them, and every host key is pinned (see `docs/SSH_HOST_KEY_VERIFICATION.md`), so the fallback does not weaken host authentication against a device that supports SHA-2. | Dropping support for SHA-1-only devices; then upgrade to paramiko 5 (Dependabot is told to skip that major update until then). |

Removed instead of accepted:

- `ecdsa` (CVE-2024-23342, Minerva timing attack, no fix planned) came in
  through `python-jose`. Access tokens now use PyJWT, and `python-jose`,
  `ecdsa`, `rsa` and `pyasn1` are no longer installed.
