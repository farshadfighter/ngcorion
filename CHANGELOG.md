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
- The license server's address is fixed: `https://lic.ngcorion.com`, part of
  the code next to its signing key, verified against the public certificate
  authorities. `LICENSE_SERVER_URL` and `LICENSE_SERVER_CA_BUNDLE` are no
  longer read (a leftover value only logs a warning).

### Release images carry the code

- The backend image contains all code and the built frontend; the checkout is
  no longer mounted into the container (`./app`, `front/dist`, `pyproject.toml`,
  `uv.lock`). Inside the image the code is root-owned and read-only for the
  application user. Development with live code: `docker-compose.dev.yml`.
- A `.dockerignore` keeps `.env`, TLS keys under `traefik/certs`, the git
  history, tests and local environments out of the image. Before, the whole
  checkout was copied in, including `.env`.
- The installation's `.env` (SECRET_KEY, SMTP, ...) is handed to the backend
  as environment variables (`env_file` in docker-compose.yml); the app used to
  find it only because it had been copied into the image.
- `deploy.sh` no longer needs Node.js on the host; it builds
  `ngcorion/backend:<version>` and keeps the previous image for rollback.
- Base images and the Python package index are build arguments
  (`BASE_REGISTRY`, `PYPI_INDEX`, `NPM_REGISTRY`); the defaults stay the
  Iranian mirrors. CI builds the image and checks it starts, answers and
  contains nothing it should not.

### Virtual appliance

- `appliance/build.sh` builds NGCorion as a virtual appliance: an OVA for
  VMware (EFI, Secure Boot, pvscsi, vmxnet3, deploy-time settings in
  vCenter), a VHDX for Hyper-V and a qcow2 for KVM/Proxmox. Ubuntu 24.04 LTS
  with Docker and every container image preloaded; no internet access needed.
- First start on the console: host name, network, NTP and the web
  administrator's password; the connection to lic.ngcorion.com is checked. Each appliance makes its
  own secrets, database password, certificate and machine-id. The same
  values can come from vCenter's OVF properties for an unattended start.
- Afterwards the console shows a menu (status, network, host name, NTP,
  license server connection check, restart, log, admin password reset,
  reboot, shut down).
  No shell, no SSH, no login prompt on any terminal, root locked, GRUB
  entries cannot be edited.

### Dependencies

- React 19, Vite 8, ESLint 10; FastAPI 0.142, Alembic 1.20, Netmiko 4.8,
  cryptography 50.0.2.

### Upgrade notes

- Images built before this release contain the `.env` of the checkout they
  were built from, if it had one. After upgrading, delete the old backend
  image (Compose named it after the folder, e.g. `ngcorion-backend`; see
  `docker images`), and rotate those secrets if such an image ever left the host.
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
