# Report — Risk settings moved from manual seed into an Alembic data migration

**Date:** 2026-08-13 · **Repo:** NGCorion backend · **DB:** PostgreSQL

> ## ⛔ DEPLOY GATE — read before shipping the entrypoint change
>
> The new `entrypoint.sh` / `Dockerfile.netease` change makes the container run
> `alembic upgrade head` automatically on start. **Do NOT deploy that change to
> staging or production until each of those environments has been checked with
> `scripts/check_alembic_stamp.py` (step 1 below) and, if the verdict is
> `UNSTAMPED, SCHEMA MATCHES HEAD`, stamped once with `alembic stamp head`
> (runbook in step 2).** An environment whose tables were built by
> `create_all()` but never stamped will otherwise crash-loop on startup with
> `DuplicateTable`. Dev is confirmed `IN SYNC` and safe.

## What I inspected first (findings)

- **Migration history:** current head was `f1a2b3c4d5e6`
  (`20260807_add_very_high_to_risklevelenum.py`). Risk chain:
  `931114c3a14b` (tables) → `a4c2d91e7b30` (permission) → `f1a2b3c4d5e6`.
- **DB engine:** PostgreSQL (`postgresql+psycopg://…`). psycopg **v3** — the
  bare `postgresql://` default resolves to psycopg2 which isn't installed, so
  CLI runs need `DATABASE_URL=postgresql+psycopg://…`.
- **Automatic migrations on container start: NO.** `Dockerfile.netease` CMD ran
  `uvicorn` directly; `docker-compose.yml` backend service had no command
  override. Migrations were **not** run automatically anywhere.
- **But the seed was not purely manual:** `app/main.py` runs
  `Base.metadata.create_all()` at import **and** calls `seed_risk_defaults(db)`
  in its lifespan startup (wrapped in try/except). So the 8 rows *were* being
  inserted on app boot — but silently swallowed on failure and dependent on app
  startup rather than the canonical `alembic upgrade head` schema contract.

## Changes

| File | Change |
|------|--------|
| `alembic/versions/20260813_add_missing_risk_settings.py` | **New** revision `d4f6a8b0c2e1` (down_revision `f1a2b3c4d5e6`, now head). Idempotent data migration. |
| `app/modules/risk/seed.py` | Removed the 8 rows from `DEFAULT_SETTINGS`; added a comment that migration `d4f6a8b0c2e1` now owns them. The other 13 settings + 7 zones stay in the seed. |
| `entrypoint.sh` | **New.** Runs `alembic upgrade head` (with `set -e`) then `exec "$@"`. |
| `Dockerfile.netease` | Added `RUN chmod +x /app/entrypoint.sh` + `ENTRYPOINT ["/app/entrypoint.sh"]` to **both** the `development` and `production` stages; CMDs unchanged. |

### Rows moved (seed → migration)

All `value_type=int`, `is_editable=True`:

| setting_key | value |
|---|---|
| criticality_low_score | 25 |
| criticality_medium_score | 50 |
| criticality_high_score | 75 |
| criticality_critical_score | 100 |
| risk_level_medium_threshold | 20 |
| risk_level_high_threshold | 40 |
| risk_level_very_high_threshold | 60 |
| risk_level_critical_threshold | 80 |

### Migration design

- Uses `sa.table`/`sa.column` bound to the migration connection — **no ORM
  imports**, so the migration is independent of application models.
- `upgrade()` inserts via PostgreSQL
  `insert(...).on_conflict_do_nothing(index_elements=["setting_key"])` →
  re-running (or running where the seed already inserted the rows) is a no-op and
  never clobbers operator customizations.
- `downgrade()` deletes **exactly** the 8 `setting_key` values, nothing else.
- Pure data migration — no `create_table`/`add_column`. The `risk_settings`
  columns already exist (created by `931114c3a14b`).

## Testing (all against the real dev PostgreSQL DB, only the 8 keys touched)

- `alembic history` / `heads`: new revision is head, correctly chained.
- **up → down → up cycle:**
  - upgrade with rows already present → `ON CONFLICT DO NOTHING`, stays 8 (no error).
  - downgrade → 8 rows deleted (count 0).
  - upgrade with rows absent → 8 rows inserted (count 8). DB left at head.
- **Seed no longer owns them:** after downgrade (0 rows), running
  `python -m app.modules.risk.seed` still reported 0 of 8 present → confirmed the
  seed no longer inserts these.
- **`GET /api/risk/settings` surfaces them:** `_settings_dict(db)` (what the
  endpoint returns) includes all 8 with correct typed values after
  `alembic upgrade head`, **with no manual seed step** (21 keys total).
- **Regression:** full risk test suite `34 passed`.
- `sh -n entrypoint.sh` passes.

## Caveat / risk to confirm

**Auto-running `alembic upgrade head` on container start interacts with the
existing `Base.metadata.create_all()` landmine** (project memory
`alembic-createall-drift`). If a deployment's DB has tables created by
`create_all` but was **never stamped**, `alembic upgrade head` replays from base
and can die on the first `create_table` with `DuplicateTable`, crash-looping the
container. Remediate once with `alembic stamp head` (or the correct revision)
then restart. The **dev DB is already at head**, so it is safe there; verify
staging/production are stamped before the next rebuild.

---

# Landmine resolution (create_all / stamp) — added 2026-08-13

## 1. Stamp-safety check — `scripts/check_alembic_stamp.py`

A **read-only** script (makes no writes: it only reads `alembic_version`,
inspects the DB's table list, and parses this repo's migration files). It
classifies a target DB and tells you whether `alembic upgrade head` is safe.

### How to run it against any environment

```bash
# Preferred: pass the environment's DATABASE_URL as an argument (read-only).
python scripts/check_alembic_stamp.py "postgresql+psycopg://USER:PASS@HOST:5432/DBNAME"

# Or via env var:
DATABASE_URL="postgresql+psycopg://USER:PASS@HOST/DBNAME" python scripts/check_alembic_stamp.py

# Verify the classifier itself (no DB needed):
python scripts/check_alembic_stamp.py --self-test
```

A bare `postgresql://…` URL is auto-rewritten to `postgresql+psycopg://…` (this
project ships psycopg v3). **Run it yourself in each environment** — I did not
run it against staging/production.

### What it reports

- Whether `alembic_version` exists and at which revision(s).
- Whether that revision is a real ancestor of head (`d4f6a8b0c2e1`) and how many
  migrations are pending.
- Which migration-created tables already exist vs. are missing (37 expected at head).

### Verdict → exit code → action

| Verdict | Exit | Action |
|---------|------|--------|
| **CLEAN** (no migration tables yet) | 0 | `upgrade head` builds from base — safe to deploy entrypoint |
| **IN SYNC** (valid stamp, ancestor of head) | 0 | `upgrade head` applies pending or is a no-op — safe |
| **UNSTAMPED, SCHEMA MATCHES HEAD** | 2 | Run `alembic stamp head` ONCE first (step 2), then safe |
| **MANUAL REVIEW** (unknown/multiple/off-chain stamp) | 3 | Do not auto-run; reconcile history manually |
| **UNSTAMPED, does NOT cleanly match head** | 3 | Do not auto-run; manual review (e.g. a pure create_all DB missing migration-only tables like `audit_module_logs`) |

**Validated:** all 8 decision branches pass `--self-test`; the live dev DB
classifies as `IN SYNC (already at head)` (37/37 tables, stamped `d4f6a8b0c2e1`).
Limitation: table-granularity only — it does not verify column-level drift.

## 2. Runbook — the "UNSTAMPED, SCHEMA MATCHES HEAD" case

Run **once per environment** that the check flags with exit code 2. Every step
is a human-run, manual step — **do not** wire `stamp` into the entrypoint.

1. **Inspect before touching anything** (all read-only):
   ```bash
   cd /app                       # repo root (has alembic.ini)
   alembic current               # expect: empty / "(no current revision)"
   alembic heads                 # expect: d4f6a8b0c2e1 (head)
   python scripts/check_alembic_stamp.py "$DATABASE_URL"   # expect verdict UNSTAMPED, SCHEMA MATCHES HEAD
   ```
   Only proceed if the verdict is exactly **UNSTAMPED, SCHEMA MATCHES HEAD**.

2. **Stamp the database to head** (writes ONLY the `alembic_version` row):
   ```bash
   alembic stamp head
   ```
   What `stamp` does: creates the `alembic_version` table if absent and sets it
   to `d4f6a8b0c2e1`. What it does **NOT** do: it never creates, alters, drops,
   or touches any table or any data — it only records "this DB is at head."

3. **Verify:**
   ```bash
   alembic current               # now shows: d4f6a8b0c2e1 (head)
   alembic upgrade head          # must be a NO-OP (no "Running upgrade ..." lines)
   python scripts/check_alembic_stamp.py "$DATABASE_URL"   # now: IN SYNC (already at head)
   ```
   After this, the auto-migrating entrypoint is safe in this environment.

4. **Rollback / if something looks wrong** *before* running a real `upgrade head`:
   - If the check said anything other than `UNSTAMPED, SCHEMA MATCHES HEAD`
     (e.g. tables missing, partial match), **stop** — do not stamp. Stamping a
     DB that does not actually match head would permanently skip the migrations
     needed to reach head (silent schema drift).
   - `alembic stamp` is reversible before any upgrade: `alembic stamp base`
     (or `DELETE FROM alembic_version;`) returns to the unstamped state without
     having changed any table.
   - If unsure, capture `alembic current`, the check output, and
     `\dt` (table list), and escalate for manual review rather than upgrading.

## 3. Proposal (NOT applied) — remove `Base.metadata.create_all()` from `app/main.py`

`create_all()` is the root cause of the landmine: it builds tables outside
Alembic, so a DB can have the schema but no stamp. The long-term fix is to let
Alembic be the single source of truth and delete the startup `create_all()`.

**Where it is:** `app/main.py:104` — a top-level module statement (runs on
import, not inside the lifespan):
```python
Base.metadata.create_all(bind=engine)
```

**Other `create_all()` users (checked, and why they're unaffected):**

| Location | Role | Impact of removing main.py's call |
|----------|------|-----------------------------------|
| `scripts/init_db.py:33` | Manual dev bootstrap (admin user, asset types, …) | Independent script. NOTE: it builds tables via create_all and does **not** stamp, so a DB bootstrapped this way is exactly the "unstamped matches head" case — prefer `alembic upgrade head` for fresh DBs going forward. |
| `tests/test_user_password_update.py:22`, `tests/test_schema_value_lengths.py:112` | Test fixtures creating their own tables | Unaffected — they call create_all directly and don't import `app.main`. |
| `license_server/app/main.py:11` | Separate license-server app | Out of scope. |

**What removing it changes:** the API app would rely entirely on
`alembic upgrade head` (now run by the entrypoint) for schema. Fresh/dev
environments that previously depended on `create_all` at boot must run
migrations first (the entrypoint already does; direct `uvicorn app.main:app`
runs would need `alembic upgrade head` beforehand).

**Recommended one-line patch (apply later, with approval):**
```diff
- Base.metadata.create_all(bind=engine)
+ # Schema is owned by Alembic; run `alembic upgrade head` (the container
+ # entrypoint does this automatically). create_all() is intentionally removed
+ # so the DB is never built outside migrations (avoids unstamped-schema drift).
```

**Do this only after** every environment is confirmed `IN SYNC` (via step 1),
because once `create_all()` is gone, an environment that isn't migrated will
start with missing tables. Recommend also updating any local-dev README to say
"run `alembic upgrade head` before first start." **Left in place for now** —
pending your explicit approval.

Nothing was committed — awaiting approval.
