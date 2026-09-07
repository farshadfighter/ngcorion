# NGCorion Security Remediation Checklist

Tracked, step-by-step remediation plan derived from the pre-production security &
standards audit (OWASP WSTG baseline). Work through items in phase order — Phase 1
gates production readiness. Check each `[ ]` box only after the fix is merged **and**
the verification steps for that item pass.

Do not batch unrelated items into one commit/PR — each finding should be independently
verifiable and revertible.

---

## Phase 1 — Critical (must fix before any production traffic)

### 1.1 — Command/SQL/PowerShell injection via unsanitized hardening parameters

- **Finding / risk**: Six of seven hardening modules substitute user-supplied
  `{PARAM}` values into remote-execution templates with raw `.replace()`, no
  escaping, then execute the result on the managed target — RCE on Linux/Windows/
  Mongo/Apache hosts, SQL injection on MSSQL, extra CLI injection on Cisco/Fortinet.
  Reachable by any authenticated user with module-level `harden` permission, not
  just admins.
- **Exact code areas to inspect**:
  - `app/modules/linux/hardening/command_templates.py` — `_substitute_params`,
    `_HEREDOC_PARAMS = {"MOTD_TEXT", "BANNER_TEXT"}` (the deliberate unquoted
    exception, lines ~2263-2274)
  - `app/modules/windows/hardening/command_templates.py:365,381` +
    `app/modules/windows/hardening/winrm_executor.py` (`run_ps()` calls ~183, 232, 254)
  - `app/modules/mssql/hardening/command_templates.py:321,338` +
    `app/modules/mssql/hardening/tsql_executor.py:254` (`cursor.execute(sql)`)
  - `app/modules/mongodb/hardening/command_templates.py:401,419` +
    `app/modules/mongodb/hardening/ssh_executor.py:149-150`
  - `app/modules/apache/hardening/command_templates.py:123,131` +
    `app/modules/apache/hardening/ssh_executor.py:147`
  - `app/modules/cisco/hardening/command_parser.py:249,306`
  - `app/modules/fortinet/hardening/command_parser.py`
    (`substitute_parameters`, `validate_fortigate_syntax` — currently dead code)
  - `app/modules/fortinet/hardening/router.py` (accepts `parameters: Dict[str, str]`
    with no content validator — the shared entry point pattern repeated per module)
  - Each module's `parameter_metadata.py` (identify which params are
    `input_type="text"` / free-form vs constrained choice)
- **Required fix**:
  - Build one shared, hardened substitution helper (e.g.
    `app/core/param_substitution.py`) used by all seven modules instead of each
    reinventing its own:
    - Default: reject newlines/control characters and shell/SQL/PowerShell
      metacharacters outright for all non-heredoc, non-multiline parameters.
    - Shell targets (linux/mongodb/apache SSH executors): per-value `shlex.quote()`
      at substitution time, not a whole-string quote wrapped around the already-
      substituted command.
    - Windows targets: PowerShell-safe encoding for injected values (e.g.
      `System.Management.Automation.Language.CodeGeneration.EscapeSingleQuotedStringContent`-
      equivalent quoting, or pass values via `-EncodedCommand`/argument binding
      instead of string interpolation into the script body).
    - MSSQL: migrate `tsql_executor.py` to parameterized queries
      (`cursor.execute(sql, params)`) wherever the target statement shape allows;
      where dynamic identifiers are unavoidable, use a strict identifier allowlist/
      quoting function, never raw interpolation.
    - Cisco/Fortinet: wire the existing `validate_fortigate_syntax()` into the
      Fortinet path; add an equivalent syntax guard for Cisco IOS.
    - For the Linux heredoc exception (`MOTD_TEXT`/`BANNER_TEXT`): reject any value
      containing a line equal to (or starting with) the heredoc delimiter, or switch
      to a randomized/unguessable delimiter per invocation.
- **Security verification / regression tests**:
  - Add a shared test module (e.g. `tests/test_param_substitution_security.py`)
    that feeds the same injection-payload matrix (embedded `;`, `` ` ``, `$()`,
    `|`, newline + new command, SQL `'; DROP TABLE...--`, PowerShell
    `; Invoke-Expression`, heredoc-delimiter collision) through every module's
    substitution function and asserts the payload is rejected or neutralized
    (never lands unescaped in the built command/script/SQL string).
  - Per-module unit tests confirming legitimate multi-word/special-character values
    (e.g. a banner with punctuation, a SQL Server login with `@`) still substitute
    correctly — regression check against over-aggressive blocking.
  - Full existing hardening test suite (`tests/test_*_hardening*.py` /
    `tests/test_*_rules.py`) re-run green after the change.
- **Acceptance criteria**: No hardening module executes a substituted parameter
  value without going through the shared, tested escaping/validation path; the
  injection-payload matrix test suite passes for all seven modules; existing
  hardening functional tests remain green.
- **Status**: [x] — Implemented and verified 2026-09-06.
  - **Shared module**: `app/core/hardening_param_security.py` — new,
    zero-dependency (stdlib only) module of validation/escaping primitives
    (`ParameterSecurityError`, `validate_cli_line`, `validate_heredoc_body`,
    `validate_delimited_text`, `reject_shell_breakout_chars`,
    `reject_single_quoted_literal_breakout`, `escape_single_quoted_shell_literal`,
    `validate_path`/`validate_identifier`/`validate_host_list`,
    `escape_powershell_single_quoted`, `escape_sql_identifier_text`,
    `validate_integer`, `validate_select`). `ParameterSecurityError` subclasses
    `ValueError` so every existing router's `except ValueError -> HTTPException(400)`
    catches it with no router changes needed.
  - **Linux** (`linux/hardening/command_templates.py`): fixed the heredoc-body
    path — `SSH_BANNER_TEXT` (was missing from `_HEREDOC_PARAMS`, so it was
    shell-quoted, which corrupted legitimate banners *and* stayed vulnerable to
    delimiter collision since `shlex.quote` only wraps the whole multi-line
    value once at its start/end, not per line) is now included, and all three
    heredoc params go through `validate_heredoc_body` (rejects a value
    containing a bare `EOF` line) instead of being inserted with zero checking.
    Non-heredoc params keep the pre-existing, already-correct `shlex.quote()`.
  - **Cisco / Fortinet** (`command_parser.py` `substitute_parameters`): every
    parameter now goes through `_validated_value`, keyed off `input_type` —
    `textarea` (Cisco `BANNER_TEXT`) uses `validate_delimited_text` guarding the
    `^` banner delimiter (newlines stay allowed — legitimate multi-line
    banners); `number` uses `validate_integer` (shape only, no min/max — see
    design note below); everything else uses `validate_cli_line` (rejects
    embedded `\n`/`\r`/control chars, the actual line-injection vector over an
    interactive device CLI; printable punctuation stays usable in passwords).
    `validate_fortigate_syntax`/`validate_cisco_syntax` remain unused dead code
    (out of scope — tracked as a separate cleanup, not a security gap once this
    item's checks are in place).
  - **MongoDB / Apache** (`command_templates.py` `_substitute_parameters`/
    `get_mongodb_template_commands`/`get_mongodb_verify_commands`): had *zero*
    prior validation. Each parameter is now routed by name/`input_type` to
    `validate_path` (file paths), `validate_identifier` (OS usernames),
    `validate_host_list` (IPs), `validate_integer`/`validate_select` (numeric/
    enum fields, bounds and options enforced from metadata), or
    `reject_shell_breakout_chars` (free text: denies `' `` $ \ ; \n \r \0`,
    keeps `| : ! - ~` etc. usable since every remaining free-text field is
    always embedded inside an existing quoted region, never a bare word).
    MongoDB's `AUDIT_FILTER` is the one exception: its documented format
    (`parameter_metadata.py`) *requires* embedded single quotes for JSON
    strings, which conflicts with denying `'` outright, so it uses
    `escape_single_quoted_shell_literal` (the standard POSIX `'\''` technique)
    instead — proven correct with an actual `sh -c` subprocess round-trip test,
    not just a Python-level assertion (see test file).
  - **MSSQL / Windows**: found to already have working, tested denylist
    validation wired into their real execution sink (`tsql_executor.
    _validate_mssql_parameters`, `winrm_executor._validate_windows_parameters`)
    — left those untouched to avoid regressing tested code for no security
    gain. The one real gap found: their *preview* endpoints
    (`get_mssql_template_statements`/`get_windows_template_statements`, called
    directly by `router.py`'s "get commands" preview action) built T-SQL/
    PowerShell with **no** validation at all. Closed by adding
    `_validated_parameters()` inside `command_templates.py` that calls the
    existing executor-side validator (deferred import to avoid a circular
    import, since the executor modules import `command_templates.py` at load
    time) — so preview and real execution now share one validated path,
    without changing the tested validators' behavior or error-message text.
  - **Design decision — no min/max/select enforcement for Cisco/Fortinet
    numbers**: an early version also enforced `min_value`/`max_value`/`options`
    from parameter metadata for Cisco/Fortinet, matching MSSQL/Windows. Reverted
    after it broke two things that are legitimate, pre-existing behavior: (1)
    `CIS-2.1.1.1.4`'s own template default `TIMEOUT_SEC=60` exceeds its own
    metadata's declared `max_value=59` (never enforced before, so this drift
    was latent); (2) `scripts/validate_cisco_mappings.py`'s triage tooling
    deliberately substitutes a placeholder `"TESTVAL"` for `select`-type params
    to test template structure, not real content. Range/option-membership is a
    business-logic/UX concern, not an injection vector (a value that is a plain
    integer, or that merely fails to match a dropdown's option list, cannot
    carry a CLI/shell metacharacter) — so only shape validation (single line /
    delimited-multiline / integer) is enforced for these two modules, closing
    the actual vulnerability without inventing new functional regressions.
  - **Tests**: `tests/test_hardening_param_injection.py` (99 tests, new) —
    unit coverage of every shared primitive plus an injection-payload matrix
    (embedded `'`, `` ` ``, `$()`, `\`, `;`, newline, SQL `'; DROP TABLE--`,
    PowerShell `'; Invoke-Expression`, heredoc/banner-delimiter collision) run
    through each of the seven modules' actual substitution entry point, plus
    legitimate-value regression tests (multi-line banners with punctuation,
    cipher-suite strings with `:`/`!`, space-separated SSH user lists, the
    MongoDB audit-filter's documented single-quoted-JSON format) proving
    nothing legitimate was weakened. One test drives the MongoDB
    `AUDIT_FILTER` escaping through a real `sh -c` subprocess (not just a
    Python-level assertion) to empirically prove an injected `touch` command
    embedded after a raw `'` does not execute.
  - **Verification run**: `pytest tests/ -q --ignore=tests/test_fortinet_rules.py
    --ignore=tests/test_windows_rules.py` (the two pre-existing collection
    errors, unrelated) → 988 passed, 68 failed, 47 skipped. The 68 failures are
    byte-for-byte identical (`diff`'d) with a `git stash` baseline run with none
    of this item's changes applied — all pre-existing (live-Postgres-dependent
    `test_mssql_rules.py`/`test_rule_evaluation.py`/`test_user_password_update.py`
    tests), zero regressions introduced. 988 passed = 889 pre-existing + 99 new.
  - **Remaining risk / out of scope for this item**: `validate_cisco_syntax`
    and `validate_fortigate_syntax` (dead code, never called) were left as-is —
    not required now that per-parameter validation exists, but still worth
    removing or wiring in during a later cleanup pass. Range/select-option
    enforcement for Cisco/Fortinet numeric and enum fields is intentionally not
    added (see design decision above) — a business-logic correctness gap, not
    a security one. MSSQL/Windows's own denylists (not the new shared module)
    remain the enforcement point for those two modules by design.

### 1.2 — Secrets committed to git history (`license_data.tar.gz`)

- **Finding / risk**: Commit `f8e140d` contains a real `~/.license` bundle
  (Fernet key + encrypted license/state data) still retrievable from history even
  though the working-tree copy was removed. This is the same key material
  `license_client.py` uses to authenticate to the license server.
- **Exact code areas to inspect**:
  - Git history: `git log --all --follow -- license_data.tar.gz`
  - `app/core/license_client.py` (`SecureStorage`, `_write_private`, Fernet key
    usage) to understand what the leaked key authorizes
  - License server-side: whichever record ties an activation/license id to this
    key material (for revocation)
- **Required fix**:
  - Rotate/revoke the license activation tied to the leaked key on the license
    server side.
  - Decide and execute: history rewrite (`git filter-repo`/BFG) to purge the
    blob, **or** formally accept the exposure (only if the repo's clone
    access has always been fully trusted and rotation alone is deemed sufficient) —
    this decision must be explicit, not default.
  - Confirm `.gitignore`'s `*.tar.gz` rule (already added) prevents recurrence, and
    confirm `.gitignore` itself stays tracked (`git add -f .gitignore`) since it is
    self-ignoring.
- **Security verification / regression tests**:
  - `git log --all -- license_data.tar.gz` returns nothing after history rewrite
    (if that path is chosen), or a documented risk-acceptance note exists (if not).
  - Confirm the old key material no longer authenticates against the license
    server (attempt activation with the leaked bundle → expect rejection).
  - `git check-ignore -v license_data.tar.gz` confirms it would be re-ignored if
    reintroduced.
- **Acceptance criteria**: Leaked key material is confirmed non-functional against
  the license server, and a documented decision (rewrite vs. accepted exposure) is
  recorded in this checklist or a linked ticket.
- **Status**: [ ] — Investigated and prepared 2026-09-07; **not closeable yet**,
  see below.
  - **Confirmed exposure**: `f8e140d` ("tar") added `license_data.tar.gz`; decrypted
    it (key + ciphertext are both in the same archive) and confirmed it is a real,
    non-dummy `~/.license` snapshot: `license_key` (format `WVOI-####-####-LGJ0`),
    `organization_token` (64-char hex — the HMAC-SHA256 shared secret
    `license_server/app/routers/licenses.py:verify_request_signature` checks
    against `license.organization_token`), `vm_fingerprint` (64-char hex, a
    server-side equality check, not independently verified), `plan_type: unlimited`.
    Together these three values are **sufficient on their own** to forge signed
    `/validate` and `/heartbeat` requests indefinitely — no additional secret or
    real hardware needed. `activate_license` binds `vm_fingerprint` on first use,
    so the license can't be hijacked onto a new machine, but ongoing
    validate/heartbeat/consume traffic can be forged. Removed from the working
    tree in `8f5f909`, but still fully retrievable from history
    (`git show f8e140d:license_data.tar.gz`) and present on `origin/main` (GitHub).
  - **Scope confirmed via full-history search**: this is the *only* occurrence —
    no other commit/branch/path ever contained `.license.key`/`.license.dat`/
    `.state.dat`/`license_data*`, and the decrypted `license_key` string appears
    nowhere else in history (`git log --all -S`). Current working tree, `.env.example`,
    and all app code are clean; `_ensure_key()` always generates a fresh random
    Fernet key per machine, never a fixed default — the leaked key is not
    hardcoded or reused anywhere in the codebase.
  - **`.gitignore` hardened**: added `*.tar`/`*.tgz` and explicit patterns for the
    raw (un-archived) SecureStorage filenames — `.license/`, `.license.key`,
    `.license.dat`, `.state.dat`, `license_data*` — since the existing `*.tar.gz`/
    `*.zip` rules alone wouldn't stop someone committing the raw files directly.
    Verified via `git check-ignore -v` against 9 variants, and confirmed no
    currently-tracked file is caught by the new patterns.
  - **Rotation — NOT performed, requires the license server admin**: the license
    server has no "regenerate token" endpoint; the only path is
    revoke/deactivate the `WVOI-3...LGJ0` record (`DELETE /api/admin/licenses/
    {license_key}`) and, if it's a live customer, issue a replacement (fresh
    `license_key`/`organization_token` are `secrets.token_hex`-generated per
    `create_license`). This repo has no network access to the actual deployed
    license server, so I could not check whether the record is still active or
    perform the rotation — per instruction, did not invent or silently rotate
    production credentials. **This is the step that actually neutralizes the
    leak** and is the reason this item stays unchecked.
  - **History rewrite — prepared and rehearsed, NOT executed**: validated
    `git filter-repo --path license_data.tar.gz --invert-paths --force` in an
    isolated local mirror clone (never touched the real repo or GitHub).
    Measured impact: 45 commits on `main` get new SHAs (`f8e140d` + its 44
    descendants); the 909 commits before it are byte-identical; `front-end`
    is completely unaffected (never merged the offending commit); the
    rewritten `main` HEAD has the identical tree hash to the real repo's
    current HEAD (no working-tree content changes, only historical commit
    identity from `f8e140d` onward). `origin` is a real GitHub remote —
    completing the purge requires a force-push of `main`, which rewrites
    shared history (anyone else with a clone must re-clone/hard-reset, open
    PRs against old commits break) and GitHub may retain old objects for a
    time regardless (fork/cache retention). Not run against the real repo or
    pushed anywhere — awaiting explicit authorization per instruction.
  - **Decision recorded 2026-09-07**: asked the user whether to run the
    rehearsed rewrite now; chose **"do nothing yet — wait for rotation
    first"** — correct sequencing, since rotation is what actually stops the
    leaked credential from being usable, while the history purge is hygiene
    (prevents *new* clones from finding it) and can follow once rotation is
    confirmed. No history rewrite was performed; nothing pushed or forced.
  - **Remaining actions (manual/production, outside this session's authority)**:
    (1) look up and revoke/reissue license `WVOI-3...LGJ0` on the license
    server — do this first; (2) once confirmed, re-run this item (or a
    follow-up session) to execute the already-rehearsed `git filter-repo`
    rewrite and decide on force-pushing; (3) if pushed, everyone with a
    clone must re-clone or hard-reset to the new history.

### 1.3 — SSH host keys never verified (MITM on every managed connection)

- **Finding / risk**: `paramiko.AutoAddPolicy()` trusts any host key presented,
  with no pinning/`known_hosts` check/operator warning. An on-path attacker can
  transparently MITM SSH sessions to managed devices, harvesting device admin
  credentials or tampering with hardening commands in transit.
- **Exact code areas to inspect**:
  - `app/modules/linux/common/fast_ssh_runner.py:92,104-105`
    (`set_missing_host_key_policy(paramiko.AutoAddPolicy())`, `look_for_keys=False`,
    `allow_agent=False`)
  - Netmiko-based clients — check default host-key behavior:
    `app/modules/cisco/**` (SSH connection setup), `app/modules/fortinet/**`
    (SSH connection setup), `app/modules/mongodb/hardening/ssh_executor.py`,
    `app/modules/apache/hardening/ssh_executor.py`
- **Required fix**:
  - Replace `AutoAddPolicy` with a policy that either (a) verifies against a
    stored `known_hosts` entry per managed asset (persisted at first-trust with
    explicit operator confirmation in the UI, keyed to the asset record), or
    (b) at minimum logs/surfaces a warning + requires an explicit "trust this
    host key" action on first connect and on any subsequent key change.
  - Audit and align the netmiko-based modules to the same policy (netmiko's
    default is equally permissive unless `ssh_config_file`/host key checking is
    explicitly configured).
- **Security verification / regression tests**:
  - Unit test with a mock/paramiko-transport double asserting connection is
    refused (or flagged) when the presented host key doesn't match the stored
    one.
  - Integration test: first connection to a new asset stores its host key; a
    second connection with a different key is rejected/flagged, not silently
    accepted.
  - Existing SSH-dependent hardening/audit tests remain green.
- **Acceptance criteria**: No SSH client in the codebase uses `AutoAddPolicy()` (or
  netmiko's unauthenticated equivalent) without an explicit, documented
  risk-accepted exception; host-key mismatches are detectable and blockable.
- **Status**: [x] — Implemented and verified 2026-09-07.
  - **Shared layer**: `app/core/ssh_host_keys.py` — one policy, one store, for
    every SSH path. Modes via `SSH_HOST_KEY_POLICY`: `tofu` (default — pin on
    first sight with a WARNING carrying the SHA256 fingerprint, reject any later
    change) and `strict` (only pre-provisioned hosts). There is deliberately **no**
    "off" mode; a legitimately re-keyed device is handled per-host via
    `ssh-keygen -R` / `forget_host()`, so no global bypass can be left switched
    on. Store is standard OpenSSH `known_hosts` format at
    `SSH_KNOWN_HOSTS_FILE`, defaulting to `/etc/ngcorion/known_hosts` (already
    bind-mounted in docker-compose.yml, so pins survive container recreation)
    with a `~/.ngcorion/known_hosts` fallback for bare-metal/dev — no manual
    configuration needed in either case. Writes are `flock`-guarded and atomic
    because production runs `uvicorn --workers 4`.
  - **SSH paths found and fixed (7 connection sites, 5 in-app + 2 in a script)**:
    | Path | Client | Before | After |
    |---|---|---|---|
    | Linux + Apache + MongoDB **hardening** | `linux/common/fast_ssh_runner.py` (paramiko) | explicit `AutoAddPolicy()` | `VerifyingHostKeyPolicy` on a deliberately empty in-client store, so *every* connection is evaluated |
    | Linux + Apache **audit** | `linux/common/ssh_client.py` (netmiko) | netmiko default = AutoAdd | pre-flight + `ssh_strict=True` + our store |
    | Cisco audit + hardening | `cisco/audit/ssh_client.py` | netmiko default | same |
    | FortiGate audit + hardening | `fortinet/audit/ssh_client.py` | netmiko default | same (pre-flight hoisted outside the two-`device_type` fallback loop) |
    | MongoDB audit | `mongodb/audit/mongo_client.py` | netmiko default | same |
    | `scripts/fortinet_audit_cli.py` (×2 sites) | standalone netmiko CLI | netmiko default | uses the app store when importable, else `ssh_strict=True` + operator's `~/.ssh/known_hosts` — stays runnable standalone, never trusts blindly |
  - **Why the split enforcement**: paramiko lets us install a policy, so that
    path decides unknown/match/mismatch itself with precise exceptions and no
    extra round trip. netmiko owns its `SSHClient` and only exposes
    `ssh_strict`/`alt_key_file`, so it gets `ensure_host_key_trusted()` first
    (which touches the network *only* when the host is unknown, to learn the key
    for pinning) plus `RejectPolicy` against the same file.
  - **netmiko error-mangling fixed**: netmiko funnels every paramiko
    `SSHException` — `BadHostKeyException` and `RejectPolicy`'s "not found in
    known_hosts" included — into `NetmikoAuthenticationException`, so a MITM
    would have been reported to the operator as a wrong password.
    `classify_netmiko_auth_failure()` reclassifies those in all four netmiko
    clients. New errors `SSHHostKeyUnknownError`/`SSHHostKeyMismatchError`
    subclass the existing `SSHHostKeyError`, so the routers that already handled
    host-key failures keep working with no router changes.
  - **Bug caught in review** (now regression-tested): paramiko hands the policy
    an already-formatted `[host]:port` name for non-default ports. Re-deriving
    an entry name from it produced `[[host]:port]:port`, which would have looked
    "unknown" on every connection and silently re-pinned — defeating change
    detection on non-22 ports. Fixed with `split_entry_name()`; the test fake was
    made faithful to paramiko so it fails without the fix.
  - **Existing behaviour preserved**: no device needs manual provisioning under
    the default `tofu` mode — first contact pins and connects exactly as before.
    Password-only auth (`look_for_keys=False`, `allow_agent=False`), retry
    budgets, timeouts and sudo wrapping are untouched; host-key failures are
    excluded from retries (a device's key will not change between attempts) and
    a probe against an unreachable device reports the true network/timeout error
    rather than a trust error the operator cannot act on.
  - **Tests**: `tests/test_ssh_host_key_verification.py` (60 tests) — unknown key
    rejected, correct key accepted, changed key rejected (incl. on non-default
    ports), auth/connection behaviour unaffected after verification, audit and
    hardening paths sharing one store, and the hardening dry-run preview
    asserted to open no SSH connection at all. Verified meaningful by mutation:
    restoring `AutoAddPolicy` fails 11 tests, `ssh_strict=False` fails 5,
    a no-op pre-flight fails 13, reverting the bracket fix fails 2.
  - **Verification run**: full suite → 1048 passed / 68 failed / 47 skipped; the
    68 failures are byte-for-byte identical (`diff`'d) to the pre-change baseline
    (pre-existing live-Postgres-dependent tests). Targeted SSH + hardening +
    module suites: 595 passed, 47 skipped.
  - **Repo-wide sweep**: `AutoAddPolicy` now appears only in documentation and in
    the test asserting it is *not* used; every `ConnectHandler(` site passes the
    strict kwargs; the single `paramiko.SSHClient()` site uses the verifying
    policy; nothing sets `ssh_strict=False`/`StrictHostKeyChecking=no`; the only
    raw `paramiko.Transport` is the credential-free probe inside the
    verification module itself.
  - **Operational docs**: `docs/SSH_HOST_KEY_VERIFICATION.md` (key-change
    remediation, pre-provisioning for `strict`, migration path, what operators
    see) and `.env.example`.
  - **Residual risk**: `tofu` still trusts the *first* contact with a device — an
    attacker already in position before a device is first audited would have
    their key pinned. Mitigation is documented: verify the logged fingerprints
    out of band, then move the deployment to `SSH_HOST_KEY_POLICY=strict`.

---

## Phase 2 — High (before external/customer exposure)

### 2.1 — CORS: wildcard origin + credentials

- **Finding / risk**: `allow_origins=["*"]` combined with `allow_credentials=True`
  causes Starlette to reflect the caller's actual `Origin`, allowing any origin to
  make authenticated cross-origin requests.
- **Exact code areas to inspect**:
  - `app/core/config.py:42` (`BACKEND_CORS_ORIGINS: List[str] = ["*"]`)
  - `app/main.py` (CORS middleware setup: `allow_credentials`, `allow_methods`,
    `allow_headers`, `expose_headers`)
  - `.env.example` / deployment `.env` docs for the production origin list
- **Required fix**:
  - Default `BACKEND_CORS_ORIGINS` to an explicit, required list (fail closed if
    unset in production, mirroring `require_license_server_url()`); document the
    production frontend origin(s) in `.env.example`.
  - Narrow `allow_methods`/`allow_headers` to what the frontend actually needs
    instead of `["*"]`, if practical without breaking functionality.
- **Security verification / regression tests**:
  - Automated test hitting a protected endpoint with an arbitrary `Origin` header
    not on the allowlist and asserting no `Access-Control-Allow-Origin` reflecting
    that origin is returned.
  - Confirm the legitimate frontend origin still receives correct CORS headers
    (no functional regression).
- **Acceptance criteria**: CORS origin list is explicit and environment-required in
  production; wildcard + credentials combination no longer present.
- **Status**: [x] — Implemented and verified 2026-09-07.
  - **Key finding that shaped the fix**: CORS was never actually needed by this
    product. `front/src/config/api.js` uses a *relative* base URL (`''`) and the
    backend serves `front/dist` itself, so production requests are same-origin;
    in dev, `front/vite.config.js` proxies `/api` and `/auth` to the backend, so
    that is same-origin too. Auth is a `Authorization: Bearer` header from
    `localStorage`, not cookies. So an **empty** allowlist is both the most
    secure setting and fully functional — no origin needs to be configured for
    either environment.
  - **`app/core/config.py`**: default changed from `["*"]` to `""` (empty).
    Added `resolve_cors_origins()` + `_normalize_cors_origin()` +
    `CORSConfigurationError`, following the existing `require_license_server_url()`
    fail-fast convention. Origins are normalized to the exact form browsers send
    (lowercased, no trailing slash) and validated; `*`, `null`, embedded
    wildcards, missing/non-http schemes, paths, queries and userinfo are all
    **refused at startup** rather than silently ignored — Starlette matches
    origins by exact string equality, so an entry that merely looks right would
    otherwise be a dead allowlist entry the operator believes is protecting them.
  - **`app/main.py`**: `allow_origins` now comes from the validated resolver;
    `allow_methods` narrowed `["*"]` → `["GET","POST","PUT","DELETE","OPTIONS"]`
    (the verbs the API actually exposes), `allow_headers` narrowed → 
    `["Authorization","Content-Type","Accept","X-Requested-With"]`,
    `expose_headers` narrowed `["*"]` → `["Content-Disposition"]` (downloads).
    The middleware stays installed even with an empty list so a cross-origin
    preflight gets an explicit "Disallowed CORS origin" instead of a confusing
    405, and startup logs which mode is active.
  - **Field typed `str`, not `List[str]`** — caught during end-to-end
    verification: pydantic-settings JSON-decodes a `List[str]` env var *before*
    our code runs, so the documented comma-separated form
    (`BACKEND_CORS_ORIGINS=https://a,https://b`) raised `SettingsError` and took
    the whole app down. Parsing moved into `cors_origins`, which accepts a JSON
    list, a comma-separated list, or a single origin. Regression-tested.
  - **License Server fixed too** (`license_server/app/main.py` + its
    `core/config.py`): it had the *identical* `allow_origins=["*"]` +
    `allow_credentials=True`, and worse, its admin endpoints use HTTP Basic auth
    — which browsers do send as CORS credentials. Now an explicit `CORS_ORIGINS`
    allowlist (default empty, wildcards refused). Safe because its admin UI is
    served same-origin behind nginx (`license-admin-ui/nginx.conf` proxies
    `/api/`) and the NGCorion backend is a server-to-server client. Included
    because this item required repo-wide confirmation that no
    wildcard+credentials pairing remains; the services were otherwise untouched.
  - **Tests**: `tests/test_cors_policy.py` (56 tests) covering all seven required
    cases — trusted origin allowed, untrusted granted nothing (incl. suffix/query/
    scheme/port lookalikes), wildcard+credentials refused, multiple origins,
    authenticated bearer requests from an allowed origin, preflight for allowed/
    untrusted/empty/disallowed-method, and "missing config never becomes `*`".
    Plus normalization, `Vary: Origin`, and assertions against the **real**
    `app.main` middleware options so the shipped config cannot drift from what
    the tests prove. Requests are driven straight through ASGI (starlette's
    TestClient needs httpx, which this project does not depend on). Verified
    meaningful by mutation: restoring the original config fails 3 tests + 4
    errors; making the resolver pass `*` through fails 3; making an empty config
    default to `*` fails 5.
  - **Verification**: full suite 1104 passed / 68 failed / 47 skipped — the 68
    are byte-for-byte identical (`diff`'d) to the pre-change baseline
    (pre-existing live-Postgres tests). Zero regressions. End-to-end env-var
    checks confirm all four documented config forms produce the right allowlist
    and that both `*` spellings refuse to boot.
  - **Repo-wide sweep**: no `allow_origins` containing a wildcard remains, no
    `allow_methods`/`allow_headers`/`expose_headers` wildcards, no
    `allow_origin_regex`, and no middleware/proxy (Traefik, nginx) emits
    `Access-Control-*` headers outside the CORS middleware.
  - **Deployment**: no action needed for the standard deployment. Documented in
    `.env.example` (and `license-admin-ui/.env.example` for the case where
    `VITE_LICENSE_API_URL` makes the admin UI cross-origin and the license
    server's `CORS_ORIGINS` must then list it).
  - **Remaining risk / note**: `LicenseMiddleware` is registered after
    `CORSMiddleware`, so it runs *outside* it — a license-invalid 503 on
    `/api/*` returns without CORS headers, which a genuine cross-origin browser
    client would see as a CORS error rather than a readable 503. Pre-existing,
    no effect on the same-origin deployment, and out of scope for this item.

### 2.2 — Docker/infra: privileged backend container + exposed Traefik dashboard

- **Finding / risk**: `backend` runs as `user: root` with `cap_add: [SYS_TIME,
  NET_ADMIN]` and host bind-mounts (`/etc/snmp`, `/etc/rsyslog.d`,
  `/etc/systemd/timesyncd.conf`, `/etc/ngcorion`, `/usr/bin/timedatectl`,
  `/run/systemd`); any RCE elsewhere lands in a container with host-systemd
  access. Traefik's `--api.insecure=true` plus unrestricted `8080:8080` exposes
  the full routing topology unauthenticated.
- **Exact code areas to inspect**:
  - `docker-compose.yml` — `backend` service (`user:`, `cap_add:`, `volumes:`
    host mounts), `traefik` service (`--api.insecure=true`, `ports: "8080:8080"`)
  - Compare against `deploy/docker-compose.license.yml` (`LICENSE_BIND_ADDR`
    scoping pattern already used correctly there)
- **Required fix**:
  - Run `backend` as a non-root user; scope `cap_add` down to only the specific
    capability actually required per host-mount use case (split into a dedicated
    sidecar if `NET_ADMIN`/`SYS_TIME` is only needed for one narrow function).
  - Disable `--api.insecure=true`; if the dashboard is needed, put it behind
    Traefik's own auth middleware and/or bind `8080` to localhost/an admin-only
    network, matching the license stack's `LICENSE_BIND_ADDR` pattern.
- **Security verification / regression tests**:
  - `docker inspect` on the running backend container confirms non-root UID and
    the reduced capability set.
  - `curl` from outside the host to port 8080 confirms the Traefik API/dashboard
    is unreachable (connection refused or 401/403).
  - Full application smoke test (login, an audit run, a hardening dry-run) passes
    under the reduced-privilege container to confirm no functionality silently
    depended on root/the removed capabilities.
- **Acceptance criteria**: Backend container runs unprivileged with minimum
  required capabilities; Traefik management plane is not reachable unauthenticated
  from outside the trusted network.
- **Status**: [ ]

### 2.3 — `SECRET_KEY` insecure default with no startup guard

- **Finding / risk**: JWT signing key falls back to a public, hardcoded literal
  string when unset, with no fail-fast check (unlike `LICENSE_SERVER_URL`). A
  misconfigured deployment boots normally and silently signs/accepts forged JWTs
  for any user/role.
- **Exact code areas to inspect**:
  - `app/core/config.py:34` (`SECRET_KEY` default), `require_license_server_url()`
    (lines 146-161, the pattern to mirror)
  - `app/core/security.py` (`create_access_token`, uses `settings.SECRET_KEY`)
  - App startup path (`app/main.py` or equivalent lifespan/startup hook) where the
    new guard should be invoked
- **Required fix**:
  - Add `require_secret_key()` (or equivalent) called at startup: raise if
    `SECRET_KEY` is unset, empty, shorter than 32 chars, or equals the known
    default literal.
  - Update `.env.example` / deployment docs to require `openssl rand -hex 32`
    generation before first boot.
- **Security verification / regression tests**:
  - Startup test: app fails to start (raises `RuntimeError` or equivalent) when
    `SECRET_KEY` is unset or equals the default literal.
  - Startup test: app starts normally with a properly generated key.
  - `tests/conftest.py` already sets a non-default `SECRET_KEY` for tests —
    confirm this continues to satisfy the new guard.
- **Acceptance criteria**: A deployment cannot boot with the default/empty/short
  `SECRET_KEY`; existing test suite's `SECRET_KEY` override continues to pass.
- **Status**: [ ]

### 2.4 — No session revocation / no logout endpoint

- **Finding / risk**: No `/logout` route, no token blacklist/deny-list, and
  password change doesn't invalidate existing tokens. A stolen JWT (frontend
  stores it in `localStorage`, readable by any XSS) stays valid for its full
  120-minute lifetime with no server-side kill switch.
- **Exact code areas to inspect**:
  - `app/modules/auth/router.py` (existing routes: `/login`, `/me`,
    `/forgot-password`, `/reset-password` — confirm no `/logout`)
  - `app/core/dependencies.py` (`get_current_user` — where a revocation check
    would need to be added)
  - `app/models/user.py` (or equivalent — where a `token_version`/
    `tokens_valid_after` column would live)
  - `front/src/store/authSlice.jsx:120` (`localStorage.setItem("token", ...)`)
- **Required fix**:
  - Add a `token_version` (or `tokens_valid_after: datetime`) column on `User`;
    embed it in the JWT payload at issuance; `get_current_user` rejects tokens
    whose embedded version/timestamp doesn't match the current DB value.
  - Bump the version/timestamp on explicit logout, on password change, and
    optionally on admin-initiated "force logout".
  - Add `POST /auth/logout` that bumps the version for the current user (and, on
    the frontend, clears `localStorage`).
  - Separately (tracked here, not fixed here): evaluate moving the token out of
    `localStorage` into an httpOnly cookie or in-memory storage as a follow-up
    hardening step against XSS token theft — note as a linked future item if
    deferred.
- **Security verification / regression tests**:
  - Test: login → call `/logout` → previously issued token is rejected by any
    protected endpoint (401).
  - Test: login → change password → old token is rejected.
  - Test: a token issued before the feature (no version claim, if migrating
    existing sessions) is handled per the chosen migration strategy (either
    grandfathered until expiry or force-invalidated — decide explicitly).
- **Acceptance criteria**: `/auth/logout` exists and works; a compromised token can
  be killed server-side without waiting out its natural expiry; password change
  invalidates prior sessions.
- **Status**: [ ]

### 2.5 — Unreliable client IP behind reverse proxy (rate-limit bypass + audit log integrity)

- **Finding / risk**: uvicorn runs without `--proxy-headers`/
  `--forwarded-allow-ips` behind Traefik in production, so `request.client.host`
  is Traefik's internal container IP for every request — collapsing the per-IP
  login rate limiter into one shared bucket, and making `LoginLog.ip_address`
  useless for real attribution in a security-auditing product.
- **Exact code areas to inspect**:
  - `Dockerfile.ngcorion` (uvicorn launch command/args)
  - `app/core/auth_rate_limiter.py` (how IP is read for `MAX_FAILURES_PER_IP`)
  - Wherever `LoginLog.ip_address` / `log_login_attempt` is populated
    (`app/modules/auth/router.py` and its service layer)
  - `docker-compose.yml` (`traefik` service — confirm forwarded-header behavior
    it sends)
- **Required fix**:
  - Launch uvicorn with `--proxy-headers --forwarded-allow-ips=<traefik container
    IP/CIDR>` (or configure via `ProxyHeadersMiddleware` if not using the CLI
    flags).
  - Confirm Traefik is configured to set `X-Forwarded-For` correctly (it does by
    default; verify no `entryPoints.*.forwardedHeaders` override disables it).
  - Switch any direct `request.client.host` reads used for rate limiting/audit
    logging to FastAPI's resolved client host once proxy headers are trusted.
- **Security verification / regression tests**:
  - Integration test: two requests from different real source IPs but through
    the same Traefik proxy produce different `LoginLog.ip_address` values and
    separate rate-limit buckets.
  - Negative test: a spoofed `X-Forwarded-For` header from a non-trusted address
    (outside `--forwarded-allow-ips`) is not honored.
- **Acceptance criteria**: Real client IP is recorded in audit logs and used for
  rate limiting in the deployed (behind-Traefik) configuration; spoofed forwarded
  headers from untrusted sources are ignored.
- **Status**: [ ]

### 2.6 — Excel formula injection on asset export

- **Finding / risk**: Asset field values are written into exported `.xlsx` cells
  with no neutralization of leading `=`/`+`/`-`/`@`. A user who can edit an asset
  can plant a formula payload (DDE/`HYPERLINK` exfiltration) that executes when
  an admin opens the export.
- **Exact code areas to inspect**:
  - `app/utils/excel_utils.py` (`export_assets_to_excel_grouped`,
    `export_assets_to_excel` — the `ws.cell(row=..., column=..., value=value)`
    calls)
  - `app/modules/assets/router_with_auth.py` (`export_assets_excel` endpoint, to
    confirm all export paths route through the same utility)
- **Required fix**:
  - Add a sanitization helper applied to every cell value: if the value's first
    character is one of `= + - @` (or a tab/CR that could precede one), prefix it
    with `'` (or space) so Excel/LibreOffice treats it as literal text, not a
    formula.
  - Apply consistently across every export function, not just the grouped one.
- **Security verification / regression tests**:
  - Unit test: an asset field set to `=HYPERLINK("http://evil","x")` (and
    `+cmd|'/c calc'!A1`, `-2+3`, `@SUM(1,1)`) is exported with a neutralizing
    prefix in the resulting cell.
  - Regression test: normal values (including ones that legitimately start with
    `-` for negative numbers stored as text, if any) still render correctly.
- **Acceptance criteria**: No exported cell value can be interpreted as a formula
  by a spreadsheet application regardless of the source asset field content.
- **Status**: [ ]

---

## Phase 3 — Medium / Hygiene

### 3.1 — Weak default admin credentials, no forced rotation

- **Finding / risk**: `scripts/init_db.py` bootstraps `admin`/`123456` with
  nothing forcing a password change on first login;
  `license_server/app/core/config.py` has an equivalent `ADMIN_PASSWORD: str =
  "changeme"` code-level default (mitigated at the deploy layer by
  `LICENSE_ADMIN_PASSWORD:?` in compose, but not at the code level).
- **Exact code areas to inspect**:
  - `scripts/init_db.py` (bootstrap admin creation)
  - `license_server/app/core/config.py` (`ADMIN_PASSWORD` default)
  - `app/models/user.py` (for a `must_change_password` flag, if adding one)
  - Login flow in `app/modules/auth/router.py` / frontend login redirect logic
- **Required fix**:
  - Generate a random bootstrap password (printed once to console/log on first
    `init_db.py` run) instead of a hardcoded weak default, or require an
    `--admin-password` argument.
  - Add a `must_change_password` flag set on bootstrap-created accounts; enforce
    a redirect-to-change-password on first login until cleared.
- **Security verification / regression tests**:
  - Test: freshly bootstrapped admin account cannot access non-password-change
    endpoints until password is changed.
  - Test: `init_db.py` no longer creates a account with a hardcoded literal
    password value.
- **Acceptance criteria**: No code path creates a privileged account with a fixed,
  publicly-known password that remains usable indefinitely.
- **Status**: [ ]

### 3.2 — Non-constant-time credential comparison (license admin panel)

- **Finding / risk**: `credentials.username != settings.ADMIN_USERNAME or
  credentials.password != settings.ADMIN_PASSWORD` uses plain `!=`, a timing
  side-channel.
- **Exact code areas to inspect**:
  - `license_server/app/routers/admin.py:24`
- **Required fix**:
  - Replace with `hmac.compare_digest()` for both username and password
    comparisons (encode to bytes first).
- **Security verification / regression tests**:
  - Unit test: valid credentials still authenticate; invalid ones (including
    correct-username/wrong-password and vice versa) are still rejected.
  - Optional: timing-variance smoke test (not required to be rigorous, just
    confirm `compare_digest` is actually in the code path).
- **Acceptance criteria**: Credential comparison uses a constant-time function.
- **Status**: [ ]

### 3.3 — Swagger UI / OpenAPI schema reachable without authentication

- **Finding / risk**: Custom `/docs` route (re-added after disabling the default)
  and `/openapi.json` have no auth dependency, exposing the full API surface to
  anyone who can reach the server.
- **Exact code areas to inspect**:
  - `app/main.py` (`docs_url=None`, custom `/docs` route, `openapi.json` route)
- **Required fix**:
  - Gate `/docs` and `/openapi.json` behind an auth dependency in production
    (e.g. require an authenticated admin session, or disable entirely and only
    enable via an env flag for internal/staging use), OR restrict at the
    reverse-proxy layer to an internal network only.
- **Security verification / regression tests**:
  - Test: unauthenticated request to `/docs` and `/openapi.json` in
    production-mode config returns 401/403/404 (per chosen approach).
  - Test: the docs remain reachable in a dev/staging config if that's the
    intended behavior (documented, not accidental).
- **Acceptance criteria**: API schema/docs are not publicly enumerable in the
  production deployment configuration.
- **Status**: [ ]

### 3.4 — SSRF surface via admin-configurable SMS provider URL

- **Finding / risk**: `send_test_sms` POSTs to an admin-configured `base` URL for
  the generic provider branch; only reachable by an already-privileged admin
  today, but an unrestricted outbound POST target is a standing SSRF primitive if
  this configuration surface widens.
- **Exact code areas to inspect**:
  - `app/modules/system_config/service.py` (`send_test_sms`, the generic-provider
    branch)
- **Required fix**:
  - Add an allowlist (or at minimum block private/link-local/loopback CIDR
    ranges — `127.0.0.0/8`, `169.254.0.0/16`, `10.0.0.0/8`,
    `172.16.0.0/12`, `192.168.0.0/16`) on the configurable `base` URL's resolved
    target before issuing the request.
- **Security verification / regression tests**:
  - Test: configuring `base` to a loopback/private-range/link-local address
    (e.g. `http://169.254.169.254/`) is rejected before the request is sent.
  - Test: a legitimate external SMS provider URL still works.
- **Acceptance criteria**: The SMS test-send path cannot be used to reach internal/
  metadata-service network targets.
- **Status**: [ ]

### 3.5 — No forced password-change-on-first-login for any bootstrap/admin-created account

- **Finding / risk**: Beyond the specific `init_db.py` default (3.1), there is no
  general mechanism requiring a password change when an admin creates an account
  on behalf of another user.
- **Exact code areas to inspect**:
  - `app/modules/users/router.py` (user-creation endpoint(s))
  - `app/models/user.py` (candidate `must_change_password` flag — shared with 3.1)
- **Required fix**:
  - Extend the `must_change_password` flag (from 3.1) to all admin-created
    accounts, not just the bootstrap admin; enforce the same first-login redirect.
- **Security verification / regression tests**:
  - Test: an account created by an admin with a temporary password cannot access
    the app until the password is changed.
- **Acceptance criteria**: Every account creation path (bootstrap and
  admin-created) results in a forced password change before first real use.
- **Status**: [ ]

### 3.6 — Dependency currency — establish an ongoing process control

- **Finding / risk**: Current versions checked (`fastapi==0.141.1`,
  `python-jose==3.5.0`, `paramiko==4.0.0`, `netmiko==4.7.0`,
  `cryptography==50.0.1`, `starlette==1.6.0`) are all current with no known-CVE
  versions pinned — this is a point-in-time check, not an ongoing guarantee.
- **Exact code areas to inspect**:
  - `pyproject.toml` / `uv.lock` (backend), `front/package.json` /
    `package-lock.json` (frontend)
- **Required fix**:
  - Add a scheduled `pip-audit` (or `uv` equivalent) and `npm audit` check —
    either a CI job or a documented periodic manual step — rather than a one-time
    pass.
- **Security verification / regression tests**:
  - CI job (or documented runbook step) runs `pip-audit`/`npm audit` and fails/
    flags on new high/critical CVEs.
- **Acceptance criteria**: A repeatable dependency-vulnerability check exists and
  is scheduled, not just a one-time snapshot.
- **Status**: [ ]

### 3.7 — Deeper logging-for-secrets sweep

- **Finding / risk**: A sampling grep for password/token logging found nothing,
  but this was not exhaustive (e.g. didn't cover exception handlers that might
  dump request bodies, or third-party library debug logging).
- **Exact code areas to inspect**:
  - All `logger.*`/`print(...)` call sites across `app/`, especially in
    exception handlers and request/response middleware
  - `app/middleware/` (any request-logging middleware) for raw body/header
    logging that could capture `Authorization` headers or password fields
- **Required fix**:
  - Complete an exhaustive review (or add a lint rule / pre-commit hook flagging
    `logger.*password*`, `logger.*token*`, `logger.*secret*` patterns).
  - Ensure any request/response logging middleware redacts `Authorization`,
    `password`, `token`, `secret` fields.
- **Security verification / regression tests**:
  - Test: trigger a login failure, a password reset, and a generic 500 error;
    inspect captured log output for the test run and assert no plaintext
    credential/token appears.
- **Acceptance criteria**: No code path logs credentials, tokens, or secrets in
  plaintext, verified by both static review and a runtime log-capture test.
- **Status**: [ ]

### 3.8 — `package.json`/`package-lock.json` at repo root (cleanup carryover)

- **Finding / risk**: Stray root-level `package.json` (only
  `{"dependencies": {"claude": "^0.1.1"}}`, no `node_modules`) unreferenced
  anywhere — looks like an accidental `npm install` at repo root instead of
  inside `front/`. `git rm` was blocked in the prior cleanup pass and never
  completed.
- **Exact code areas to inspect**:
  - Repo root `package.json`, `package-lock.json`
- **Required fix**:
  - Confirm still unreferenced (re-run reference trace), then remove via `git rm`.
- **Security verification / regression tests**:
  - `npm run build` in `front/` and `python -c "import app.main"` still succeed
    after removal.
- **Acceptance criteria**: File removed with no build/import breakage, or a
  documented reason found for keeping it.
- **Status**: [ ]

---

## Cross-cutting notes

- **MFA**: Not implemented anywhere in the auth flow. Explicitly out of scope for
  this checklist (documented as an accepted scoping decision for an internal
  admin tool) unless the user decides otherwise — revisit if NGCorion becomes
  externally exposed.
- **Positive findings (already verified, no action needed, re-check only if
  surrounding code changes)**:
  - `get_current_user` re-validates role from the DB on every request; JWT
    `role` claim is never trusted for authorization directly.
  - `users/router.py` blocks self-role/permission escalation
    (`user_id == current_user.id` guard).
  - `assert_session_access`/`owner_scope` in `app/core/dependencies.py` return
    404 (not 403) for other users' sessions — correct IDOR posture.
  - No `debug=True`, no stack-trace-leaking exception handler found.
  - Nmap scan target validated via strict regex/CIDR restriction — not
    vulnerable to argument injection.
  - `system_config/service.py` subprocess calls use argv lists, not `shell=True`.

## How to use this document

1. Work top to bottom within each phase; do not start Phase 2 items until all
   Phase 1 boxes are checked.
2. For each item: implement the fix in its own branch/PR, run the listed
   verification steps, get the fix reviewed, then check the box here in the same
   PR that merges the fix (or immediately after, referencing the PR).
3. If a fix is deferred or an item's acceptance criteria change, update that
   item's entry directly rather than leaving this document stale — this file is
   the source of truth for remediation status.
