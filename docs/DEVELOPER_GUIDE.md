# Developer guide

Read [ARCHITECTURE.md](ARCHITECTURE.md) first; this guide assumes its
vocabulary (modules, benchmark engine, dumps, rules, templates).

## 1. Ground rules

These are not style preferences. Each one closes a class of security bug,
and review will send a change back that breaks one of them.

1. **Every route authenticates and authorizes.** Use
   `Depends(require_permission("<module>", "read"|"write"|"delete"))`,
   `require_admin` or `require_admin_or_manager`, never only
   `get_current_user` for something that changes state. Object-level
   ownership (audit sessions) goes through `assert_session_access` and
   `owner_scope`: list queries use `owned_sessions(query, owner_scope(user))`,
   and any request body or path that names a session, audit result or
   hardening action is checked with `require_own_session`,
   `require_own_result` or `require_own_action` before anything else.
2. **Device credentials are never stored** unless the feature is explicitly
   about keeping them (scheduled jobs, SNMP, notification channels, backup
   destinations), and then only encrypted with `app/core/credential_crypto.py`
   under a purpose of its own. Never log them, never return them from the API.
3. **Nothing from a user reaches a shell, PowerShell, SQL or device CLI
   unvalidated.** Use typed parameters (`ParamMeta` / the module's parameter
   metadata) and `app/core/hardening_param_security.py`; numbers are
   substituted in canonical form, options from their list, text through the
   deny-list and a regex. Database access uses SQLAlchemy or bound
   parameters only (`text(...)` with `:params`, `psycopg.sql` for
   identifiers).
4. **Device identity is verified** before credentials are sent (SSH host-key
   pinning, `tls_pins` for HTTPS APIs). Do not add a connection path that
   skips it.
5. **Outbound URLs that an administrator configures** (webhooks, SMS
   gateways) go through `reject_ssrf_target`, with redirects off.
6. **Secrets in collected output are redacted before storage** (`redact` of
   the module spec, `app/core/secret_redaction.py`).
7. **Every state-changing action is audit-logged** with `log_action`
   (who, what, target, result).
8. **The schema changes only through Alembic migrations**, one head
   (`uv run alembic heads` must print one line).
9. **No license or authentication bypass**, not even "temporarily" or behind
   a flag. Licensing decisions come only from verified signed tokens
   (`app/core/license_token.py`); never act on an unsigned field of a license
   server answer, and never make the trusted keys configurable. For local
   development run the real license server with a development key and add its
   public key to `app/core/license_keys.py` in your working copy only; the
   committed list holds only lic.ngcorion.com's key
   (`tests/test_license_keys.py` checks each entry's id against its key).

## 2. Code conventions

- Python 3.13, FastAPI, SQLAlchemy (classic `Column` style, as in the rest of
  `app/models`), Pydantic v2.
- Each module and each public function or class starts with a docstring
  that says *what it is for and why*, not a restatement of the code. Comments
  inside functions explain decisions a reader could not guess (a device quirk,
  a security reason, an ordering constraint).
- Errors a user can act on are `HTTPException` with a plain-English `detail`;
  the UI translates known sentences (`front/src/i18n/backendText.js`).
  Unexpected exceptions are logged with `logger.exception` and answered with
  a generic message: no stack traces or internal paths in responses.
- Frontend: function components and hooks, Redux Toolkit slices for server
  data, the shared axios instance `src/config/api.js`, plain CSS per area
  scoped under a class of its own (global class names leak between pages).
  Every visible string goes through `t()`.
- Tests next to the behaviour they protect: a bug fix comes with a test that
  fails without it.
- The production image runs the `app` package compiled with Cython
  (`scripts/compile_app.py`); development and the tests use the source. Code
  must behave the same both ways, so:
  - no logic that reads its own source (`inspect.getsource`) or a closure's
    cells (`__closure__`); attach what callers need as an attribute instead
    (see `require_permission`);
  - modules are not reloaded at run time (`importlib.reload` cannot re-run a
    compiled module);
  - a Pydantic model with a plain method or a `computed_field` cannot be
    compiled: put such models in one of the modules listed in
    `KEEP_AS_SOURCE`, or add the module there. Licensing, permission and
    asset-limit code may never be added to it (`MUST_COMPILE`; the build fails).
  To try a compiled tree locally: `pip install cython==3.2.4 setuptools`, then
  `python scripts/compile_app.py --keep-sources` in a copy of the checkout.

## 3. Running things locally

```bash
uv sync --group dev                       # backend dependencies
uv run alembic upgrade head               # schema
uv run uvicorn app.main:app --reload      # API on :8000
cd front && npm ci && VITE_BACKEND_URL=http://127.0.0.1:8000 npm run dev
```

Checks before a push (CI runs the same):

```bash
uvx ruff@0.15.8 check app tests alembic   # rules in pyproject.toml [tool.ruff]
uv run pytest -q
cd front && npm run lint && npm test && npm run i18n:check && npm run build
```

`tests/conftest.py` defaults `DATABASE_URL` to
`postgresql+psycopg://netease:1234@localhost/netease_db`; apply the
migrations to that database first.

## 4. Recipes

### 4.1 Add an API endpoint to an existing module

1. Request/response models in the module's `schemas.py`.
2. Logic in `service.py` (no HTTP types there, so it can be tested and reused).
3. The route in `router.py` with the right `require_permission(...)`; call
   `log_action` for changes.
4. If the module is new, include its router in `app/main.py`.
5. Tests in `tests/test_<module>*.py`: the happy path, the permission
   refusal, invalid input.

### 4.2 Add a database table or column

1. Model in `app/models/<domain>.py`; import it in `app/models/__init__.py`.
2. Migration: `uv run alembic revision -m "<what and why>"`, set
   `down_revision` to the current head, write `upgrade()` and `downgrade()`
   by hand. New non-null columns need a `server_default`.
3. `uv run alembic upgrade head` locally, then the full test suite.
4. The system backup copies every table. A table that belongs to this
   server only and must survive a restore unchanged goes into `LOCAL_TABLES`
   in `app/modules/sysbackup/dbdump.py`.

### 4.3 Add a page to the UI

1. Component under `front/src/components/<Area>/`, styles under
   `front/src/assets/` scoped by the page's root class.
2. Register it in `front/src/components/routePages.jsx` (lazy import) and
   add a `<Route>` in `front/src/App.jsx` inside
   `<RequirePermission module="..." name="...">`.
3. Sidebar entry in `front/src/components/DashboardLayout.jsx`: a
   `usePermission(module, "read")` gate, the item itself, its title in
   `pageTitles`, and the path in `menuFromPath`.
4. A new permission module also goes into `ModuleEnum`
   (`app/models/user_permission.py`) and
   `front/src/components/UserManagement/permissionModules.js`.
5. `npm run i18n:extract`, then translate the new keys in
   `src/i18n/locales/fa/<area>.json`.

### 4.4 Add an audit/hardening target (benchmark module)

The ESXi (`app/modules/esxi`), NGINX (`app/modules/nginx`) and Sophos
(`app/modules/sophos`) modules are complete, recent examples; copy the one
whose transport is closest.

Backend:

1. `app/modules/<key>/`:
   - `collect.py`: `COMMANDS` (section name -> read-only command) and
     `collect(conn)`; redact secrets.
   - `rules.py`: `BenchmarkRule`s with id, title, severity, sections read,
     a check function returning pass/fail plus evidence, and the
     remediation text; `rules_for(dump)` picks the ones that apply.
   - `hardening.py`: a `TemplateSet` with fix and verify statements and
     typed `ParamMeta`s. Every fix must have a verify that prints `PASS`.
   - `spec.py`: the `ModuleSpec`.
2. A new transport: a connector in `app/modules/benchmark/connectors.py`
   (its credential fields become the request model of the routers).
3. Register the spec in `app/modules/benchmark/registry.py`.
4. `DeviceType` value in `app/models/audit.py` plus a migration
   (`ALTER TYPE devicetype ADD VALUE IF NOT EXISTS '...'`, see
   `alembic/versions/d7a0f2b4c9e1_sophos_devicetype.py`).
5. Catalog and classification: `app/core/target_catalog.py` (the target
   picker), `app/utils/device_classification.py` (which assets it applies
   to), `app/modules/software/catalog.py` (product name for CVE matching),
   `app/modules/reports/templates.py` (label), and the audit-log module name
   in `app/modules/cisco/audit/audit_logs_router.py`.
6. Tests: a captured or constructed dump in `tests/mock_data/<key>/`, rule
   tests on it, template rendering tests, and an emulator or a real
   instance for the end-to-end path.

Frontend:

7. `front/src/components/Hardening/hardeningCredentials.js` (credential
   fields, label, benchmark name), `Auditing/AuditingForm.jsx` and
   `Hardening/HardeningConnectionForm.jsx` (any target-specific hint),
   `store/auditSlice.jsx` (`AUDIT_FAMILIES`), `store/hardeningSlice.jsx`
   (label and request mapping), `Scheduling/ScheduledJobsPage.jsx`.
8. Translations: `npm run i18n:extract`, then fill in `locales/fa`; rule
   texts the API sends go into `i18n/backendText.js`.

### 4.5 Add a background task

Write `start_x()` / `stop_x()` (an asyncio loop that tolerates errors and
sleeps between runs), and add `SingletonTask("x", start_x, stop_x)` to the
list in the lifespan of `app/main.py`. Add its name to the health detail
(`app/modules/system_health.py`) so an administrator can see it is alive.

## 5. Translations (i18n)

- `t("English sentence")` everywhere in the UI; placeholders as
  `t("{{count}} assets", { count })`.
- `npm run i18n:extract` adds new keys (empty) to `locales/fa/*.json` and
  removes unused ones; `npm run i18n:check` (CI) fails on any empty one.
- Text that comes from the API in English is translated with `tb()`; add
  the sentence (or a `{{placeholder}}` template) to `i18n/backendText.js`.
- Numbers shown to the user go through `n()` (Persian digits in Persian).
- Mixed-direction text (Persian with paths, commands, versions) needs
  `dir="auto"` on its element.

## 6. Releasing

1. `VERSION` in `app/core/config.py` (shown in `/health` and the UI).
2. Green CI on `main`.
3. Deploy with `deploy.sh`: it pulls, builds the backend image
   `ngcorion/backend:<VERSION>` (the image builds the frontend and carries all
   code; nothing is mounted from the checkout), tags it `latest` and restarts
   the container, which applies migrations on start. The previous version's
   image stays on the host for a rollback.
