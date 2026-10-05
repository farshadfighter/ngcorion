# NGCorion architecture

This document explains how the parts of NGCorion fit together: what runs
where, how a request is handled, how an audit and a hardening run work, and
where state lives. The developer guide ([DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md))
builds on it with conventions and step-by-step recipes.

## 1. Runtime

```
 browser ──HTTPS──> Traefik ──HTTP──> backend container (uvicorn, 4 workers)
                                        ├─ FastAPI app (app/main.py)
                                        │    ├─ /auth/*, /api/*  JSON API
                                        │    └─ everything else: the built React app (front/dist)
                                        ├─ background tasks (one leader worker, see 5.)
                                        └─ outbound: SSH / WinRM / HTTPS to audited devices,
                                           SNMP (NOC), NVD/OSV feeds, SMTP/SMS/webhooks, license server
                                      PostgreSQL (all state)
```

- The backend serves the frontend itself (same origin), so the browser never
  needs CORS. `BACKEND_CORS_ORIGINS` exists only for a separately hosted UI.
- Production runs uvicorn with several workers. Every worker serves requests,
  but each background loop runs in exactly one of them (section 5).
- `entrypoint.sh` drops root to UID 10001, applies `alembic upgrade head`,
  then starts the server.

## 2. A request, end to end

Middleware, outermost first (`app/main.py`):

1. **SecurityHeadersMiddleware** (`app/middleware/security_headers.py`):
   CSP, X-Frame-Options DENY, nosniff, HSTS over HTTPS, `no-store` on the
   API. It is outermost so even short-circuited responses carry the headers.
2. **CORSMiddleware**: explicit, validated allowlist only.
3. **LicenseMiddleware** (`app/middleware/license_middleware.py`): refuses
   `/api/*` while no valid license is known (login, health and license
   endpoints pass through). The license state comes from the license server
   and is cached on disk, with an offline grace window. See section 9.
4. **MaintenanceMiddleware**: turns requests away while a system-backup
   restore swaps the database.

Then the route's dependencies (`app/core/dependencies.py`):

- `get_current_user` decodes the bearer JWT (PyJWT, HS256), refuses
  revoked tokens (server-side logout, table `revoked_tokens`) and tokens
  whose password fingerprint (`pwv` claim) no longer matches (password
  changed), then loads the user from the database. Role and permissions
  always come from the database, never from the token. An account whose
  password was chosen by someone else (`users.must_change_password`) only
  reaches the password-change and session endpoints.
- `require_permission(module, "read" | "write" | "delete")` checks the
  per-module permission table (`app/models/user_permission.py`, `ModuleEnum`).
  Admins pass every check. The frontend mirrors the same module list in
  `front/src/components/UserManagement/permissionModules.js`.
- `require_admin`, `require_admin_or_manager` are role checks for
  administration endpoints.
- Audit sessions are owned: `assert_session_access` / `owner_scope` let a
  non-admin see only their own sessions (404 for anyone else's). Listings,
  counts, histories and statistics filter with `owned_sessions`; a hardening
  request that names a session, a finding or an action goes through
  `require_own_session`, `require_own_result` or `require_own_action`.
- `check_quota_available` / `consume_quota_on_success` enforce the license
  quota for audits and hardening runs.

Every state-changing action is written to the audit log
(`app/models/security_audit_log.py`, `log_action`).

## 3. Code layout (backend)

| Path | Contents |
|---|---|
| `app/main.py` | App factory: middleware, every router, lifespan (startup checks, background tasks) |
| `app/core/` | Settings (`config.py`), DB session (`database.py`), auth (`security.py`, `dependencies.py`), rate limiters, encryption of stored secrets (`credential_crypto.py`), SSH host-key and TLS certificate pinning (`ssh_host_keys.py`, `tls_pins.py`), hardening parameter validation (`hardening_param_security.py`), the target catalog (`target_catalog.py`), leader election for background loops (`singleton.py`), license client and state |
| `app/models/` | SQLAlchemy models, one file per domain; `__init__.py` imports them all so Alembic and relationships see every table |
| `app/modules/<area>/` | One package per feature, usually `router.py` (HTTP), `service.py` (logic), `schemas.py` (Pydantic), plus engines, collectors and parsers |
| `app/modules/benchmark/` | The shared audit/hardening engine of the newer target modules (section 4) |
| `app/modules/shared/` | Pieces shared by the older target modules (hardening router helpers, audit logging) |
| `app/utils/` | Excel import/export, device classification of assets |
| `alembic/versions/` | Migrations; the schema changes only through them |

Target modules come in two generations:

- **Older modules** (`cisco`, `fortinet`, `linux`, `windows`, `apache`,
  `mongodb`, `mssql`) each have their own `audit/` and `hardening/`
  packages: SSH or WinRM client, command list, rules, command templates,
  parameter metadata, executor.
- **Benchmark modules** (`active_directory`, `dns_server`, `dhcp_server`,
  `iis`, `docker`, `kubernetes`, `mysql`, `esxi`, `nginx`, `sophos`) only
  declare what is specific to the target (section 4); the engine supplies the
  routers, sessions, scoring, hardening flow and logging.

## 4. The benchmark engine (audit and hardening)

A benchmark module is a `ModuleSpec` (`app/modules/benchmark/spec.py`)
registered in `app/modules/benchmark/registry.py`. It declares:

| Field | Meaning |
|---|---|
| `key`, `device_type` | API path segment and the `DeviceType` stored on sessions |
| `connector` | How to reach the target: a key of `CONNECTORS` in `benchmark/connectors.py` (WinRM, SSH with sudo, SSH without sudo for ESXi, the Sophos XML API, ...) |
| `collect(conn) -> str` | Runs read-only commands and returns one text **dump** made of sections (`===SECTION:NAME===`). Secrets are redacted before storage (`redact`). |
| `rules_for(dump)` | The `BenchmarkRule`s that apply to this target (version and role are detected from the dump) |
| `templates` | A `TemplateSet`: per check, the statements that fix it, the statements that verify the fix, and typed parameters (`ParamMeta`) |

**Audit** (`benchmark/audit_service.py`): connect, `collect`, store the
dump, evaluate every rule (`rules.evaluate`): each rule reads its sections and
returns pass/fail/manual with evidence. The session, results and score go to
the database; software found on the way goes to the software inventory.

**Hardening** (`benchmark/hardening_service.py`, `templates.py`):

1. Parameters are validated (`TemplateSet.validate`): numbers by range and
   substituted in canonical form, options against their list, text against
   a deny-list of shell characters and an optional regex. Credentials are
   used for the run and never stored.
2. Optional backup of the current configuration (`backup`).
3. The fix statements run; a fix counts as successful only if no statement
   reported an error (`FAILURE_PREFIXES`) **and** the verify statements
   print `PASS`.
4. "Harden All" runs many checks in one connection with the same rules.

Modules whose changes are structured edits rather than shell commands use a
small statement language executed by their connection object, for example
`NGX:` (NGINX configuration edits with `nginx -t` and rollback,
`app/modules/nginx/edit.py`) and `SFOS:` (Sophos read-modify-write over the
XML API, `app/modules/sophos/edit.py`).

Device identity is pinned: SSH host keys on first use (or strictly, see
`SSH_HOST_KEY_POLICY`) and HTTPS certificates of API-managed devices
(`tls_pins.py`); a changed key or certificate is refused before any
credential is sent. See [SSH_HOST_KEY_VERIFICATION.md](SSH_HOST_KEY_VERIFICATION.md).

## 5. Background work

Started in the lifespan of `app/main.py`, each wrapped in a `SingletonTask`
(`app/core/singleton.py`): every worker competes for a Postgres advisory
lock named after the task, and only the holder runs the loop. If that worker
dies, its connection drops, the lock is released and another worker takes
over within 30 seconds.

| Task | Module | What it does |
|---|---|---|
| job-scheduler | `scheduling` | Runs scheduled discoveries and audits (credentials stored encrypted) |
| noc-poller | `noc` | Polls devices over SNMP; interface status and metrics |
| noc-metrics-retention | `noc` | Rolls raw samples up and evicts old ones |
| cve-auto-update | `cve` | Daily CVE/KEV/EPSS and distribution-advisory updates |
| alert-engine | `alerts` | Evaluates alert rules, sends notifications |
| remediation-sync | `remediation` | Keeps remediation items in step with findings |
| report-worker | `reports` | Builds queued and scheduled reports |
| system-backup | `sysbackup` | Scheduled backups of the NGCorion database and files |

The license heartbeat runs in every worker (each keeps its own license
state). `/api/system/health` (admin) shows whether each task is running.

## 6. Data and secrets

- **PostgreSQL** holds everything. The schema is managed by Alembic only
  (`alembic upgrade head`), and CI checks that there is a single head.
  (`Base.metadata.create_all` still runs at import for development
  databases, so a new table must still get a migration.)
- **Device credentials** given for an audit or hardening run are used and
  forgotten. Credentials that must be kept (scheduled jobs, SNMP, SMTP/SMS,
  backup destinations) are encrypted with keys derived from `SECRET_KEY` per
  purpose (`app/core/credential_crypto.py`, HKDF + Fernet).
- **Passwords** of users: bcrypt. Password-reset codes: only their SHA-256
  is stored, with expiry and attempt limits.
- **Files**: report archive, system backups (`BACKUP_DIR`), CVE data,
  pinned SSH host keys and TLS certificates (next to the known-hosts file),
  license files (`LICENSE_STORAGE_DIR`).

## 7. Frontend

- React 18 + Vite, plain JavaScript (JSX), Redux Toolkit, react-router v6.
- `src/main.jsx` mounts the app; `src/App.jsx` declares routes, each wrapped in
  `RequirePermission`; pages are lazy-loaded through `src/components/routePages.jsx`.
- `src/components/DashboardLayout.jsx` is the shell (sidebar, header,
  alerts bell, user menu) and renders the page in `<Outlet />`.
- `src/store/*Slice` hold server data per area; requests go through the one
  axios instance `src/config/api.js`, which attaches the token and turns
  401/403 into logout, license, quota and permission events.
- **i18n** (`src/i18n/`): every UI string is `t("English text")`; Persian
  translations live in `src/i18n/locales/fa/<area>.json` and
  `npm run i18n:check` fails CI if one is missing. Sentences the API sends
  in English are translated at display time by `tb()` (`i18n/backendText.js`).
  Persian switches the document to RTL and uses Persian digits for numbers
  (`n()`).
- Styles are plain CSS per area under `src/assets/`; there is no CSS-in-JS.

## 8. Tests and CI

- `tests/` is a pytest suite run against a real PostgreSQL with every
  migration applied. Devices that cannot run in CI are emulated
  (`tests/fake_esxi.py`, `tests/fake_sophos.py`, `tests/benchmark_fakes.py`)
  or tested on captured dumps (`tests/mock_data/`). Tests against real
  instances (Docker, MySQL, NGINX, Kubernetes) are opt-in through
  environment variables and skipped otherwise.
- `front/` has Vitest + Testing Library tests, ESLint (no warnings allowed),
  the translation check and the production build.
- `.github/workflows/ci.yml` runs all of it plus the dependency
  vulnerability check on every push; Dependabot proposes updates.

## 9. Licensing

The license server (separate repository) decides; NGCorion only acts on
answers it can prove came from it.

- **Signed answers.** Every answer (activate, validate, heartbeat, consume)
  carries a token signed with the license server's Ed25519 private key.
  `app/core/license_token.py` verifies it against the public keys built into
  `app/core/license_keys.py` (code, not configuration, so it cannot be swapped
  in `.env`), and checks that it is about this license key and this machine and
  echoes the nonce of the request. The license state is built from the signed
  claims only (`claims_to_state`); the unsigned fields beside the token are
  ignored. An answer that does not verify is a rejection
  (`LicenseAnswerUntrusted`), never an outage.
- **Machine binding.** `app/core/machine_fingerprint.py` computes the
  fingerprint here, from the hardware/VM UUID (copied by `entrypoint.sh` as
  root) and the host's `/etc/machine-id` (mounted by docker-compose). The
  license server binds a license to one fingerprint. Installations activated
  by releases before signing carried the license server's own fingerprint; the
  client re-activates them once with the real one.
- **Offline grace and the cache.** The on-disk cache stores the last signed
  token, re-verified at startup; the 48h grace window counts from the token's
  signed issue time. A clock that goes backwards (to stretch the window) makes
  the state invalid.
- **Transport.** `LICENSE_SERVER_URL` must be https (loopback excepted): the
  requests carry the license key and organization token.
- **Limits.** Someone who can change NGCorion's own code on the server can
  still remove these checks; signing stops configuration-level bypasses (a
  fake server, an edited cache), not code modification.
