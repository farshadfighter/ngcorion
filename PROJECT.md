# PROJECT.md

## What This Project Does

**NGcorion** (internal repo name "Netease") is a network asset management and security compliance
platform for enterprises. It combines an **asset inventory / CMDB** (devices, owners, locations,
network zones, dependencies), **automated network discovery** (Nmap-driven scanning that proposes
new assets), and a **CIS Benchmark auditing & hardening engine** that connects to real
infrastructure (Cisco, Fortinet, Linux, Windows Server, Apache, MongoDB, MSSQL) over SSH/WinRM/DB
protocols, evaluates hundreds of security controls against each device, and can remediate failed
checks live — with before/after evidence, config backups, and a full audit trail. The system is
license-gated (a separate License Server issues/validates per-organization licenses with quotas)
and ships with role/permission-based multi-user access.

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python), Uvicorn |
| ORM / Migrations | SQLAlchemy 2.x + Alembic |
| Database | **PostgreSQL** (main app DB + separate license DB) |
| Auth | JWT (`python-jose`), `passlib`/`bcrypt` password hashing |
| Device connectivity | `netmiko`/`paramiko` (SSH: Cisco, Fortinet, Linux, Apache), `pywinrm` (Windows), `pymongo` (MongoDB), `pymssql` (SQL Server) |
| Rate limiting / caching | Redis (license server), in-process rate limiters (audit/auth) |
| Frontend | React 18 + Vite, Redux Toolkit (`@reduxjs/toolkit`), React Router, Recharts, Axios |
| License system | Standalone FastAPI service + Postgres + Redis, own React admin console (`license-admin-ui`) |
| Excel import/export | `openpyxl` |

## Architecture & Module Structure

Monorepo with three deployable pieces:

```
/app/                    Main backend (FastAPI) — this is "the product"
/front/                  Main product's React SPA (built to front/dist, served as static files)
/license_server/         Standalone license-issuing/validation service (own FastAPI app, own DB)
/license-admin-ui/       Standalone React admin console for the license server (no shared code)
/alembic/                DB migrations for the main app
/scripts/                Ops/debug/one-off scripts (CLI audits, mock data, migration helpers)
/tests/                  Pytest suite (rule evaluation, hardening, SSH runners, schema checks)
```

### `app/` layout

```
app/main.py               FastAPI app: middleware, router registration, lifespan (license heartbeat)
app/core/                 config, database session, security (JWT), rate limiters, license client, email
app/middleware/           LicenseMiddleware, SecurityHeadersMiddleware
app/models/               SQLAlchemy models (assets, audit, hardening, users, discovery, backups, ...)
app/schemas/               Pydantic schemas shared across modules (auth, users, logs)
app/modules/               Feature modules — see below
```

### `app/modules/` — feature modules

Each **device family** (`cisco`, `fortinet`, `linux`, `windows`, `apache`, `mongodb`, `mssql`) is a
self-contained package with an identical internal shape:

```
<family>/
  audit/
    rules.py            CIS rule definitions: id, title, severity, level, check_fn, evidence_fn
    <client>.py          Protocol client that collects raw evidence (SSH/WinRM/DB) from the device
    service.py           Orchestrates: connect -> collect -> evaluate rules -> persist AuditSession/Result
    router.py             POST /execute, GET /sessions, GET /sessions/{id}, /sessions/{id}/results, ...
  hardening/
    command_templates.py Per-check remediation command template(s), keyed by check id
    parameter_metadata.py Declares user-editable parameters a template needs (with validation)
    <executor>.py         Applies commands over SSH/WinRM/DB
    service.py             preview (dry-run) / execute-single / batch execute + post-fix verification
    router.py               POST /preview, /execute-single, GET /supported-checks, /check/{id}/template
```

Other modules:

| Module | Purpose |
|---|---|
| `app/modules/assets/` | CMDB CRUD: assets, types, owners, locations, zones, OS/vendor catalogs, dependencies, security status, Excel import/export, aggregate "views" |
| `app/modules/discovery/` | Network scanning (nmap-based), pending-host review, approve/reject/apply into asset inventory, port management |
| `app/modules/audit/` | Cross-family shared endpoints: get/delete an audit session by ID regardless of device type |
| `app/modules/hardening/` | Cross-family hardening logs; `harden_all/` = unified plan/execute contract (see below) |
| `app/modules/shared/` | Schema-driven hardening primitives: JSON-schema-defined remediation forms, validation, unified `/api/hardening/schema/*` execution |
| `app/modules/backup/` | Device configuration backups (`DeviceBackup` rows), independent of hardening's own backup column |
| `app/modules/auth/`, `users/` | Login, JWT issuance, forgot/reset password (email OTP), user CRUD, per-user module permissions |
| `app/modules/license/` | Client-side integration with the external License Server (status, activation) |
| `app/modules/logs/` | Login/security audit log viewer |

### Shared audit/hardening building blocks

- **`app/modules/shared/hardening_audit.py` / `hardening_backup.py`** — reusable helpers all
  families' hardening services call: fetch the failed `AuditResult`, snapshot config before
  changing it, record a `HardeningAction`.
- **`app/modules/shared/schemas/`** — a schema-loader/validator for hardening parameter forms so
  the frontend can render remediation inputs generically instead of hardcoding per-check UI.
- **`app/modules/hardening/harden_all/`** — a device-family-agnostic "fix everything" flow:
  `contract.py` defines one wire format (`PlanCheck`, `PlanParameter`, `CredentialField`, …) that
  every family maps onto via `families.py` adapters, so the frontend never branches on device type.

## How Auditing Works, End-to-End

1. **Client submits a target** — `POST /api/audit/{family}/execute` with an `asset_id` (or raw
   host), credentials, and (for Linux/Windows/etc.) a distro/version hint. A quota check
   (`check_quota_available("audit")`) gates the call against the active license.
2. **Connect & collect** — a protocol client (`ssh_client.py`, `winrm_client.py`, `mongo_client.py`,
   `mssql_client.py`) logs in and runs a fixed battery of read-only commands/queries, capturing
   output under `===SECTION:NAME===`-style markers (or structured JSON for Windows/Mongo/MSSQL).
   Nothing is written to the device during audit.
3. **Rule evaluation** — `rules.py` for that family holds a list of rule objects (dataclasses) each
   with a `check` function (returns pass/fail from the collected evidence) and an `evidence`
   function (extracts the relevant snippet for the report). `evaluate_compliance()` runs every
   applicable rule against the collected data.
   - **Linux** is layered: a large **flat, distro-tagged rule set** (`linux/audit/rules.py`,
     `distros=[...]` per rule) is the common baseline; `linux/rhel/`, `linux/rocky/`,
     `linux/ubuntu/` each contribute a **version-specific supplement** that's lazily imported and
     appended, gated to an exact profile (e.g. `rhel_10`) so no control is scored twice.
   - **Windows / MSSQL** use **version-aware base+delta builders**: a base rule set for the newest
     benchmark version, with thin builder functions that add/drop/override controls for older
     versions, gated by an auto-detected version string (`CurrentBuildNumber` / `@@VERSION`).
   - **Fortinet** is **VDOM-aware**: rules carry a scope (`global` / `vdom` / `vdom_root`) and the
     service can audit a single VDOM or fan out across all discovered VDOMs.
   - Controls that can't be proven programmatically (manual/GPO-only/patch-level checks) are
     reported `NOT_APPLICABLE` and excluded from the compliance score.
4. **Persistence** — an `AuditSession` (device, template, timestamp, summary counts) and one
   `AuditResult` row per check (`status`: pass/fail/not_applicable/error, evidence text) are written.
5. **Read-back** — `GET /sessions`, `/sessions/{id}`, `/sessions/{id}/results` (and
   `/sessions/{id}/failed` for Linux) serve the dashboard; `app/modules/audit/router.py` exposes
   family-agnostic get/delete-by-id for the shared UI.

## How Hardening Works, End-to-End

Two entry points exist:

**A. Per-family, per-check (interactive)**
1. `POST /api/hardening/{family}/preview` — given a failed `AuditResult`, look up its
   `command_templates.py` entry, fill in any `parameter_metadata.py`-declared parameters supplied
   by the user, and return the exact commands that *would* run (no execution).
2. `POST /api/hardening/{family}/execute-single` — connect with provided credentials, snapshot the
   current config (`hardening_backup.py`, also mirrored into `DeviceBackup` for the Backups page),
   run the commands via the family's executor (`ssh_executor.py` / `winrm_executor.py` /
   `tsql_executor.py`), then **re-run the original audit check** against fresh evidence to verify
   the fix actually took — this must fail closed and never mark the DB as PASS on an inconclusive
   verify. Everything is recorded as a `HardeningAction` (commands, output, backup, verification
   result, error, target VDOM if Fortinet).
3. Fortinet additionally supports `manual-execute` for checks that can't be templated (e.g. because
   the audit reads per-interface state the fix can't target directly), plus VDOM discovery and
   per-target device-option prompts before execution.

**B. Harden All (bulk, family-agnostic)**
- `GET /api/hardening/harden-all/session/{id}/plan` — inspects every failed result in an audit
  session and returns one unified `HardenAllPlan`: which checks are auto-fixable vs. need manual
  steps, what parameters/credentials are needed, grouped by the family adapter in `families.py`.
- `POST /api/hardening/harden-all/execute` — runs the batch across whatever family adapters apply,
  normalizing each family's own result shape into one response — the frontend renders this without
  knowing which device type it's touching.

**C. Schema-driven (generic)** — `app/modules/shared/hardening_router.py` (`/api/hardening/schema/*`)
exposes `/form` (build a parameter form from a JSON schema), `/validate`, and `/execute` for
controls modeled purely by schema rather than a bespoke per-family template.

## Supported Targets

| Family | Versions / Scope | Check Count | Notes |
|---|---|---:|---|
| **Cisco** IOS/IOS-XE | single ruleset | 39 | Enable-mode aware SSH |
| **Fortinet** FortiGate | VDOM-aware | 47 (25 automated / 22 manual) | global / vdom / vdom_root scopes; all-VDOM audit |
| **Linux — Ubuntu** | 20.04 / 22.04 / 24.04 LTS | 150 / 178 / 205 | flat baseline + version deltas |
| **Linux — RHEL** | 8 / 9 / 10 | 227 / 235 / 240 | flat baseline + RHEL supplement |
| **Linux — Rocky** | 8 / 9 / 10 | 221 / 231 / 239 | rebadged/trimmed RHEL-10 builders |
| **Windows Server** | 2016 / 2022 / 2025 | 273 each | gate auto-detected from build number; shared registry-DWORD table drives audit + hardening together |
| **Apache** (httpd) | single ruleset | 83 | |
| **MongoDB** | single ruleset | 27 | manual checks reported NOT_APPLICABLE |
| **MSSQL** | 2016 / 2019 / 2022 | 45 / 47 / 47 | version-aware, stable topic-based IDs shared across versions; auto-detected from `@@VERSION` |

*(Counts are live rule-builder totals as of this doc; see `tests/test_*_rules.py` for the
authoritative source per family.)*

## API Endpoint Map

All protected routes require a bearer JWT (`Depends(get_current_user)`); `/auth/*` is open.

| Prefix | Module | Key routes |
|---|---|---|
| `/auth` | auth | `POST /login`, `GET /me`, `POST /forgot-password`, `POST /reset-password` |
| `/api/users` | users | CRUD, `GET /modules` (permission catalog), `GET /search/` |
| `/api/logs` | logs | login log listing, per-user, stats |
| `/api/assets` | assets | CRUD, `/export/excel`, `/export/template`, `/import/excel(/upload)` |
| `/api/asset-types`, `/api/owners`, `/api/locations`, `/api/zones`, `/api/os`, `/api/vendors`, `/api/dependencies`, `/api/security`, `/api/views`, `/api/requirements` | assets | supporting CMDB CRUD + aggregate `/views/overview` etc. |
| `/api/enums` | assets | enum catalogs (status, confidentiality, risk, relation types) |
| `/api/asset-logs`, `/api/asset-requirement-logs` | assets | per-module audit-log trails |
| `/api/discovery` | discovery | `POST /scan`, `GET /scans`, `GET /pending`, `POST /hosts/{id}/approve\|reject`, `POST /bulk-approve`, `POST /apply(-bulk)`, `POST /ports/add\|overwrite` |
| `/api/discovery-logs` | discovery | scan log trail |
| `/api/audit/{cisco\|fortinet\|linux\|windows\|apache\|mongodb\|mssql}` | per-family audit | `POST /execute`, `GET /sessions(/count)`, `GET /sessions/{id}(/results\|/failed)`, `DELETE /sessions/{id}` |
| `/api/audit` | shared audit | `GET/DELETE /sessions/{id}` (family-agnostic) |
| `/api/audit-logs` | cisco audit logs | listing + `/stats/cisco` |
| `/api/hardening/{family}` | per-family hardening | `POST /preview`, `POST /execute-single` (or `/preview`, `/execute` for cisco/fortinet), `GET /supported-checks`, `GET /check/{id}/template` |
| `/api/hardening/fortinet` | fortinet hardening | + `/manual-execute`, `/manual-guidance/{id}`, `/vdoms/discover`, `/device-options/{result_id}` |
| `/api/hardening/schema` | shared schema-driven hardening | `POST /form`, `/validate`, `/execute`, `GET /devices`, `/control/{device_type}/{id}` |
| `/api/hardening/harden-all` | harden_all | `GET /session/{id}/plan`, `POST /execute` |
| `/api/hardening-logs` | hardening logs | listing, per-asset, per-session, stats |
| `/api/backups` | backup | list/get/create/delete `DeviceBackup` rows |
| `/api/license` | license | `GET /status`, `POST /activate` (talks to the external License Server) |
| `/docs` | — | custom Swagger UI (self-hosted assets, no CDN) |

## How to Run the Project

### Prerequisites
- PostgreSQL (two DBs: main app + license) and Redis — `docker-compose up -d` starts all three
  (`postgres-main:5432`, `postgres-license:5433`, `redis:6379`).
- Python 3.x with `.venv`, Node.js for the frontends.

### Backend (main app)
```bash
cp .env.example .env            # set DATABASE_URL, SECRET_KEY, LICENSE_SERVER_URL, SMTP*, etc.
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head             # apply migrations (app also does create_all on startup)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Swagger UI: `http://localhost:8000/docs`. Root/health: `GET /`, `GET /health`.

### License server (required — main app checks in via heartbeat/middleware)
```bash
cd license_server
cp .env.example .env
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --port 8001
```

### Frontend (main SPA)
```bash
cd front
npm install
npm run dev        # Vite dev server, http://localhost:5173
npm run build       # production build -> front/dist (gitignored; served by the backend/static host)
```

### License admin console (standalone)
```bash
cd license-admin-ui
npm install
npm run dev
```

### Tests
```bash
pytest tests/
```

### Ops scripts
`scripts/` has one-off/debug utilities: `init_db.py` (seed DB), `fortinet_audit_cli.py` (CLI
audit runner), `create_fortinet_mock_data.py`, `harden_ubuntu22.sh`, `verify_hardening_e2e.py`.
