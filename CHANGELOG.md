# Changelog

## 2.1.0-rc.1 — 2026-10-11 (release candidate)

### Licensing by number of assets

- A license covers a number of assets: the plan (Essential 25, Professional
  100, Business 250, Enterprise 500 / 1,000 / 2,500, Enterprise Unlimited)
  plus add-on packs of 50 assets. Audits and hardening runs are no longer
  counted; the audit/hardening quotas and the license server's `/consume`
  are gone.
- Every asset in the inventory counts. Adding an asset beyond the limit (by
  hand, by Excel import, from discovery) is refused with a clear message; an
  import or a bulk approval adds what fits and reports the rest.
- While the inventory is larger than the license covers, audits and hardening
  run only on the first assets the license covers (the oldest); the others
  stay in the inventory, marked "Outside license". Scheduled audits follow the
  same rule (before, they were not licensed at all), and so does the Cisco
  auto-audit.
- Without contact with the license server: the license's plan for 48 hours,
  then a pilot license (5 assets) for up to 30 days, then locked. The plan
  returns with the next answer from the license server; nothing changes on the
  license itself. Before, the license server overwrote the plan with the pilot
  plan for good. `LICENSE_OFFLINE_GRACE_HOURS` is no longer read.
- The License page shows the plan, assets used against the limit, add-on
  packs, expiry, the last contact with the license server, and the offline
  pilot; the asset pages show the same in the header. The heartbeat reports
  the asset count to the license server.
- Activating a license sends a heartbeat at once, so the license server sees
  the asset count from the moment of activation, not up to an hour later.

### Offline (air-gapped) licenses

- For a server without internet access: on the first-run screen or the
  License page, download a request file, have the license administrator sign
  it (license server admin console: the license must be marked offline), and
  upload the license file you get back. It is bound to this server and valid
  one year (never past the license's expiry); NGCorion then runs without any
  contact with the license server. Renewal is the same two-file exchange; the
  License page warns 30 days before the file ends.
- A file cannot be edited, forged or used on another server. A clock set back
  (before the file's issue time, or below the last time seen, also across a
  restart) invalidates the license.

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
- Slow first starts: Postgres gets 5 minutes to create its database and
  the backend 10 minutes to apply every migration before their health checks
  count, and uvicorn waits 2 minutes for a starting worker (it killed every
  worker after 5 seconds on a slow VM, in a loop).
- The installation's `.env` (SECRET_KEY, SMTP, ...) is handed to the backend
  as environment variables (`env_file` in docker-compose.yml); the app used to
  find it only because it had been copied into the image.
- `deploy.sh` no longer needs Node.js on the host; it builds
  `ngcorion/backend:<version>` and keeps the previous image for rollback.
- Base images and the Python package index are build arguments
  (`BASE_REGISTRY`, `PYPI_INDEX`, `NPM_REGISTRY`); the defaults stay the
  Iranian mirrors. CI builds the image and checks it starts, answers and
  contains nothing it should not.

### Security (AFTA review)

- Idle sessions end: a session unused for `SESSION_IDLE_TIMEOUT_MINUTES` (30)
  is ended at the server and its token revoked; the UI signs out after the
  same time without keyboard or mouse input (its automatic refreshes would
  otherwise keep a session alive on an unattended screen). New table
  `user_sessions`.
- A notice on the login page before sign-in (`LOGIN_BANNER`, or the built-in
  Persian/English one).
- The audit trail (`audit_logs`) is append-only in the database too: a
  trigger refuses changes and deletions (the backup/restore engine, which
  replaces the whole database, is the one exception).
- The sign-in history (`login_logs`) can no longer be cleared from the Logs
  page: it is an authentication record, and clearing it also reset the
  failed-login counter an attacker is held back by.
- System Configuration → Pinned device keys (administrators): the SSH host
  keys and HTTPS certificates NGCorion pinned, with the asset each belongs to,
  and *Remove pin* for a device that was reinstalled. Before, a device that
  changed its key could not be audited again on the appliance (no shell to run
  `ssh-keygen -R`). Each removal is audited with the dropped fingerprint.
- Audit trail page (System → Audit trail, Logs read permission): the whole
  security audit trail (`audit_logs`) and every sign-in attempt
  (`login_logs`), with text search, filters (module, action, result, user,
  address, date range) and paging done on the server, and CSV export of what
  the filters select. Exports are formula-safe and recorded in the trail
  (`audit_trail.export`). Before, the Logs page showed only the latest 50
  entries of each section, with no search.
- A system administrator can set a temporary password for another user who
  cannot sign in and has no email for the self-service reset (User
  Management → key button; `POST /api/users/{id}/reset-password`). The
  password meets the password policy (the dialog can generate one), the
  user's open sessions end at once, the user must choose their own password
  at the next sign-in, and the action is in the audit trail
  (`user.password_reset`, never the password). Changing a password through
  Edit user still needs the user's current password (5f147c8); before, the
  only way back for such a user was to delete and recreate the account.
- Date fields follow the interface language: in Persian every date field
  (audit trail, reports, remediation deadlines and acceptances, asset dates,
  CVE export, NOC time range, the system clock) takes and shows Jalali dates
  with Persian digits, typed (`۱۴۰۵/۰۷/۱۹`) or picked from a month calendar
  that starts on Saturday. Before, they showed the browser's Gregorian
  `mm/dd/yyyy` picker. The calendar arithmetic is checked day by day against
  ICU for 1950-2060. The report builder's period labels read "From date" /
  "To date" (the Persian "To" was the word for an email recipient).
- The audit trail reads in Persian: the detail of every event and sign-in is
  translated at display time (the stored record and the CSV keep the original
  English). `scripts/audit_messages.py` finds every sentence the code writes
  into the trail, and a test fails when a new one has no translation. The Logs
  page says it shows the latest 50 entries of each section and links to the
  audit trail.
- The sign-in history table (`login_logs`) is now created by a migration. It
  was only ever made by `create_all` at application start, so a database
  built by Alembic alone (a restore into an empty database, tools, CI) had no
  sign-in history table. CI now checks after the migrations that every model
  table exists (`scripts/check_migrations_cover_models.py`).
- License activation and offline license installation, accepted or refused,
  are written to the audit trail (`license.activate`,
  `license.offline_install`) with who did it (or the first-run screen), the
  address, and the license key masked to its first and last four characters.
- `SECRET_KEY` must have at least 32 characters and must not be a placeholder
  published in the repository (`config.py`, `.env.example`); NGCorion stops at
  start-up otherwise. It signs every session token and protects the stored
  secrets, and a short key can be brute-forced offline from one token.
- Password-reset codes are never written to the log. Without a mail server
  in `.env` (the appliance's default) the code used to be logged in clear
  instead of sent, so anyone able to read the log could reset any account.
  Reset emails now go through the mail server of System Configuration > SMTP
  (the one alerts and reports use), with the `.env` SMTP settings as a
  fallback; without either, nothing is sent and the log says so.

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
- Built on GitHub too (`.github/workflows/appliance.yml`): a version tag
  (`v2.1.0`) or a manual run builds the OVA, VHDX and qcow2 on GitHub's
  servers (KVM) and attaches them to a draft release, with SHA256SUMS.
  Images over GitHub's 2 GiB per-file limit come in parts; the release notes
  give the commands to join them.

### Compiled backend

- The production image runs the `app` package compiled to native modules
  (Cython 3.2), stripped of symbols; the `.py` sources are not in the image.
  Licensing, permissions, quotas and every feature module can no longer be
  read or edited in place on an installation. Three schema-only modules
  stay source (a Pydantic limitation); the build refuses to leave any
  licensing module uncompiled. Tests and development use the source; CI
  checks the image contains no other source and starts it.

### Documentation (AFTA)

- Persian user guide (`docs/fa/USER_GUIDE.md`, AGD_OPE), administrator guide
  covering delivery, installation, secure configuration and operation
  (`docs/fa/ADMIN_GUIDE.md`, AGD_PRE/AGD_OPE) and security architecture
  (`docs/fa/ARCHITECTURE.md`, ADV_ARC); the Security Target points to them.

### Fixes
- The audit trail's date range counts whole days in the time zone set in
  System Configuration, as reports do; before, a day ran from 03:30 to 03:30
  in Tehran (UTC days), so events after midnight landed on the wrong day.
- The asset overview (`/assets`) asks for an asset permission and the License
  page for a system administrator, as the menu already did: a direct URL now
  says "no access" instead of a half-empty page. The asset-limit dialog offers
  the License page to administrators only.
- The asset list no longer fails for everyone once the user who owned an
  asset is deleted (the owner becomes empty, which the API refused).
- `deploy.sh` starts the backend with `--remove-orphans`, so an upgrade from
  2.0.0 also stops the `redis` container the release no longer has.

Checked with an upgrade from 2.0.0 on real data: 2.0.0 database (users,
permissions, assets, sign-ins, audit events) migrated to this release, schema
identical to a fresh install, sign-in, audit trail and temporary passwords
working; a 2.0.0 backup restored into this release the same way, with the
audit trail still append-only.

### A clearer menu
- The sidebar follows the work: Assets, Security assessment (risk, audits,
  CVE), Remediation & hardening, Device backups, Network & monitoring,
  Reports, Administration; at most seven entries per group, plain names
  instead of the two "Operation & Device" entries.
- Group headings open and close their group (the current page's group stays
  open, the rest is remembered per browser); the overview pages that used to
  open only from a clickable heading are entries of their own. Collapsed, each
  group is an icon whose entries appear beside it. Entries are real links.
- Every entry needs the permission its page needs: Risk and License were shown
  to everyone, and a user without the risk permission landed on "no access".
  The license and NGCorion backup entries are for system administrators.
- Logs and the audit trail are one page, "Logs and audit trail", with the
  module activity as its third tab; `/settings/logs` opens that tab. The CVE
  database moved to Administration. Page URLs are unchanged.

### Documents as PDF
- The Persian user guide, admin guide, security architecture and Security
  Target are printed to PDF by `scripts/docs_pdf.py`: right-to-left A4 in the
  Vazirmatn font, a cover (product, version, document id, Jalali date), a
  linked table of contents, bookmarks and page numbers; links between the
  documents lead to the other PDFs. CI builds them on every push (artifact
  `ngcorion-docs-fa-pdf`) and the appliance release attaches them, listed in
  `SHA256SUMS`. The Markdown stays the source.

### Smaller deployment

- The Redis container is gone from `docker-compose.yml` and the appliance: no
  NGCorion code used it (the license server, which did, has its own). One
  service, image and volume fewer to run, patch and secure.

### Code standards

- The backend is linted in CI with ruff (pyflakes and syntax errors: unused or
  duplicate imports and variables, undefined names; rules in `pyproject.toml`).
  About 200 unused imports, dead variables and duplicate imports were removed;
  behaviour is unchanged.

### Dependencies

- React 19, Vite 8, ESLint 10; FastAPI 0.142, Alembic 1.20, Netmiko 4.8,
  cryptography 50.0.2.

### Upgrade notes

- Docker installations: start with `docker compose up -d --remove-orphans` so
  the old `redis` container is removed; the `redis_data` volume can then be
  deleted (`docker volume ls`, `docker volume rm <project>_redis_data`). The
  appliance does this by itself.
- Docker installations: check that `SECRET_KEY` in `.env` has at least 32
  characters (the appliance generates 64). A shorter key now stops the start.
  Replacing it signs everyone out and makes stored secrets (scheduled-job
  credentials, SNMP, SMTP, backup destinations) unreadable: re-enter them, or
  restore a system backup, which re-encrypts them under the new key.
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
