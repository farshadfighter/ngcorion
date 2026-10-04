# Security

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainers (not in a public
issue). Include the affected version (`/api/health` shows it), the steps to
reproduce, and the impact you observed.

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
