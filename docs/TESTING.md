# Testing Guide

How to run and write tests in this project (the FastAPI backend under `app/`).

The test runner is **pytest** (9.x), already installed in the project virtualenv at
`.venv`. Tests live in `tests/`.

---

## 1. Quick start

Always run pytest through the project venv. The reliable, repeatable invocation is:

```bash
# from the repo root: /home/sina/netease
.venv/bin/python -m pytest tests/ -q
```

Run a single file (fastest feedback loop while working on one area):

```bash
.venv/bin/python -m pytest tests/test_cisco_hardening_params.py -q
```

Run a single test, or a single parametrized case:

```bash
# one test function
.venv/bin/python -m pytest tests/test_cisco_hardening_params.py::test_manual_form_returns_params_for_cis_ids -q

# one parametrized id
.venv/bin/python -m pytest "tests/test_cisco_hardening_params.py::test_template_can_satisfy_its_check[CIS-1.1.6]" -q
```

Select by keyword (substring match on test names):

```bash
.venv/bin/python -m pytest tests/ -k "cisco and not integration" -q
```

> Tip: if you've activated the venv (`source .venv/bin/activate`) you can drop the
> `.venv/bin/python -m` prefix and just run `pytest`. Using the full prefix avoids
> accidentally running a system pytest against the wrong interpreter.

---

## 2. Project-specific rules (read these before you run anything)

There is **no `pytest.ini` / `pyproject` pytest config** in this repo, so a few
conventions are enforced by hand:

1. **Always scope to `tests/`.** Do not run a bare `pytest` from the repo root.
   The root contains `tmp/test_discovery_api.py`, a stray script that pytest will
   try to collect; it isn't a real test module and breaks collection with
   `ModuleNotFoundError: No module named 'app.modules'`, which aborts the whole run.
   Scoping to `tests/` avoids it:

   ```bash
   .venv/bin/python -m pytest tests/        # good
   .venv/bin/python -m pytest               # bad: also collects tmp/
   ```

2. **Imports work because of `tests/conftest.py`.** That file inserts the repo root
   onto `sys.path`, which is what lets tests do `from app.modules.cisco... import ...`.
   Any new test must live under `tests/` so this conftest is loaded. If you see
   `No module named 'app'`, you almost certainly ran pytest from the wrong directory
   or outside `tests/`.

3. **The suite is partially stale.** Some test files depend on a
   `tests/mock_data/` directory and on a live database that aren't present in a fresh
   checkout, so they error/fail today. This is pre-existing rot, not something your
   change broke. Check the table below before assuming a red result is your fault.

---

## 3. Current health of each test file

Status as of this writing (`.venv/bin/python -m pytest tests/<file> -q`):

| File | Status | Needs |
|------|--------|-------|
| `test_cisco_hardening_params.py` | ✅ passes (123) | nothing — pure logic |
| `test_hardening_templates.py` | ✅ passes (27) | nothing |
| `test_mssql_rules.py` | ✅ passes (94) | nothing |
| `test_windows_rules.py` | ✅ passes (160) | nothing |
| `test_audit_commands.py` | ⚠️ partial (some fail) | stale expectations |
| `test_distro_detection.py` | ⚠️ errors | `tests/mock_data/*` fixtures |
| `test_rule_evaluation.py` | ⚠️ errors | `tests/mock_data/*` fixtures |
| `test_integration.py` | ⚠️ errors/fail | mock data + DB |
| `test_user_password_update.py` | ⚠️ fails | database |

**Rule of thumb:** the rule/template/parameter logic tests (cisco, mssql, windows,
hardening templates) are the green, dependency-free core. Run those to confirm you
haven't regressed business logic. The "errors" in the others come from missing
`mock_data` / DB, not from the code under test.

---

## 4. Writing a new test

Put the file in `tests/`, name it `test_*.py`, name functions `test_*`. Prefer
**pure-logic tests** that import the relevant module directly and need no SSH device
and no database — these run fast and never flake. `tests/test_cisco_hardening_params.py`
is the model to copy.

Minimal example:

```python
# tests/test_example.py
from app.modules.cisco.hardening.command_templates import has_template, get_template


def test_template_has_no_required_params_is_auto_fixable():
    t = get_template("CIS-2.1.2")          # "no cdp run"
    assert has_template("CIS-2.1.2")
    assert t.get("required_params") == []
```

### Parametrize to cover many cases cheaply

```python
import pytest
from app.modules.cisco.hardening.command_templates import CIS_SECTION_TO_IOS, has_template

@pytest.mark.parametrize("check_id", sorted(CIS_SECTION_TO_IOS))
def test_every_mapping_resolves(check_id):
    assert has_template(check_id)
```

### Guidelines

- **No DB / no SSH** for logic tests. If you must exercise code that opens a DB session
  or an SSH connection, mock it (`unittest.mock.patch` / `MagicMock`) rather than
  requiring a live service. SQLite can stand in for Postgres in a pinch, but note that
  SQLite drops timezone info on read, so tz-aware comparisons need care.
- **Reuse, don't duplicate.** If a helper already exists (e.g. the Cisco mapping
  validator's `synthesize_config`), import it instead of re-implementing — that's how
  `test_cisco_hardening_params.py` stays in sync with `scripts/validate_cisco_mappings.py`.
- **`skip` is fine for known gaps.** Use `pytest.skip(...)` / `@pytest.mark.skip` for
  cases that can only be verified against a real device, so they're visible but don't
  fail CI.

---

## 5. Useful flags

```bash
-q                     # quieter output
-v                     # verbose: show each test id
-x                     # stop at first failure
--lf                   # re-run only last-failed
-k "expr"              # select tests by name substring/boolean expr
-s                     # don't capture stdout (see print/logging live)
--tb=short             # shorter tracebacks
-p no:cacheprovider    # don't write .pytest_cache
--collect-only         # list what would run, without running
```

Example debugging loop:

```bash
.venv/bin/python -m pytest tests/test_cisco_hardening_params.py -x -vv --tb=short
```

---

## 6. The Cisco mapping validator (not a pytest, but related)

`scripts/validate_cisco_mappings.py` is a standalone triage tool that checks every
`CIS -> command-template` mapping by synthesizing a post-fix config and running the
audit rule's `check()` against it. It catches templates that can never satisfy their
own verification. Run it after touching Cisco templates or rules:

```bash
.venv/bin/python -m scripts.validate_cisco_mappings
# exit code 0 = no mismatches; 1 = mismatches found (listed)
```

The same synthesis logic is reused by `tests/test_cisco_hardening_params.py::test_template_can_satisfy_its_check`,
so a green test run and a clean validator run mean the same thing.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|--------|-------------|
| `No module named 'app'` / `'app.modules'` | Ran pytest from the wrong dir or outside `tests/`. Run `.venv/bin/python -m pytest tests/` from the repo root. |
| Whole run aborts: "errors during collection" mentioning `tmp/` | You ran a bare `pytest`; it collected `tmp/test_discovery_api.py`. Scope to `tests/`. |
| `FileNotFoundError` for `tests/mock_data/...` | Pre-existing: those fixtures aren't in the repo. Affected files: `test_distro_detection`, `test_rule_evaluation`, `test_integration`. Not your regression. |
| DB connection / OperationalError | `test_user_password_update` and parts of `test_integration` need a database. Skip them for logic work, or bring up the DB (see `docker-compose.yml`). |
| `pytest: command not found` | Use the venv: `.venv/bin/python -m pytest ...`. |
