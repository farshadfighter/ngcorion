# Changelog

## 2.1.0 — unreleased

### Licensing can no longer be bypassed by configuration

- Every answer of the license server is signed (Ed25519). NGCorion accepts an
  answer only if it verifies against a key built into the code, is about this
  license and this machine, and echoes the request's nonce. A stand-in server
  that answers "valid" no longer unlocks anything.
- The machine fingerprint is computed on the licensed machine (hardware/VM
  UUID and the host's machine-id). Before, it came from the license server
  itself, so every installation had the same fingerprint and one license could
  run on any number of servers.
- The offline cache stores the signed token and is verified again on restart;
  the 48h grace window counts from the signed issue time, and a clock set
  back invalidates the license.
- `LICENSE_SERVER_URL` must use https (loopback excepted).

### Upgrade notes

- Requires the matching license server release (signed answers, migration
  005). Upgrade the license server first; older NGCorion releases keep working
  against it.
- Put the license server's public key into `app/core/license_keys.py`
  (license server: `scripts/generate_signing_key.py`). Without it NGCorion
  refuses every license.
- docker-compose now mounts the host's `/etc/machine-id`. On the first
  validation after the upgrade each installation re-activates once, binding
  its license to the real machine; a second copy of the same installation is
  then refused. To move a license to new hardware later, use "Release
  machine" in the license admin UI.

## 2.0.0 — 2026-10-04

### New audit and hardening targets

All on the shared benchmark engine (`app/modules/benchmark`), with typed
hardening parameters, verified fixes and Harden All:

- Active Directory (CIS domain-controller profile plus domain checks beyond CIS)
- Windows DNS Server (DISA STIG) and Windows DHCP Server (Microsoft guidance)
- IIS 10 (CIS)
- Docker (CIS Docker) and Kubernetes (CIS Kubernetes, kubeadm)
- MySQL 8 (CIS)
- VMware ESXi 7/8 (CIS)
- NGINX (CIS NGINX)
- Sophos Firewall (vendor hardening guide, XML API)

### New modules

- CVE database with online and signed offline updates (NVD, CISA KEV, EPSS)
- Distribution security advisories (Ubuntu, Debian, RHEL family via OSV)
- Software inventory per asset, with change history and CVE matching on real versions
- Remediation tracking with deadlines and risk acceptance (four-eyes approval)
- Reports: catalog of 14 reports, PDF and Excel, archive, schedules and e-mail
- Alerts and notifications (e-mail, SMS, syslog, webhooks)
- NGCorion self-backup: encrypted backups, remote destinations, verified restore
- Configuration restore from device backups with automatic revert
- Bilingual interface (Persian, right-to-left with Solar Hijri dates, and English)
- Target picker driven by the target catalog; an icon for every asset type

### Security

- Server-side logout: access tokens carry an id and are revoked on logout.
- Passwords chosen by someone else (new accounts, the first administrator)
  must be changed at first login; users can change their own password.
  `scripts/init_db.py` no longer creates a default password.
- Every audit session listing, count, history and statistic is limited to the
  caller's own sessions for non-admins, as the detail endpoints already were.
  Hardening requests must own the session, finding or action they name.
- Hardening parameters: numbers are substituted in canonical form.
- PDF reports load only the bundled fonts; Excel exports never store a formula.
- Discovery port lists, Sophos API entity names and OSV URLs are validated
  or encoded before use.
- python-jose replaced by PyJWT; CI checks dependencies for known
  vulnerabilities (pip-audit, npm audit) and Dependabot proposes updates.
- The backend container runs as an unprivileged user.

### Fixes

- Background tasks run once across uvicorn workers (leader election).
- Health checks count only this database's advisory locks.
- The hardening audit log now records the asset and session of a preview
  (it read a relationship that does not exist).
- Discovery records the MAC vendor of hosts.

### For developers

- `README.md`, `docs/ARCHITECTURE.md` and `docs/DEVELOPER_GUIDE.md` describe
  the system, its security rules and how to extend it.
- Every backend module, public class and function has a docstring; every
  frontend file starts with a comment saying what it is for.
- CI runs the backend tests on PostgreSQL, the frontend lint (no warnings),
  tests, translation check and build.

### Upgrade notes

- Apply the migrations (`alembic upgrade head`; the container does this on
  start). New tables include `revoked_tokens`; `users` gains
  `must_change_password`.
- Existing users are not forced to change their password. Accounts created
  from now on are.
- Non-admin users now see only their own audit sessions in every list.
