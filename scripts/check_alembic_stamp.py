#!/usr/bin/env python3
"""
Alembic stamp-safety check (READ-ONLY).

Purpose
-------
Before the container entrypoint (which now runs ``alembic upgrade head``
automatically) is deployed to an environment, use this to decide whether
``alembic upgrade head`` is SAFE there, or whether the database first needs a
one-time ``alembic stamp head`` (because its tables were built by
``Base.metadata.create_all()`` and it was never stamped).

This script performs NO writes: it only reads ``alembic_version``, inspects the
list of tables in the target DB, and parses this repo's migration files. It
never creates, alters, drops, stamps, or upgrades anything.

Usage
-----
    # Point it at the DB you want to check (read-only):
    DATABASE_URL="postgresql+psycopg://user:pass@host:5432/dbname" \
        python scripts/check_alembic_stamp.py

    # Or pass the URL as an argument:
    python scripts/check_alembic_stamp.py "postgresql+psycopg://user:pass@host/db"

A bare "postgresql://" URL is auto-rewritten to "postgresql+psycopg://" because
this project ships psycopg v3 (psycopg2 is not installed).

Exit codes (so it can gate a deploy step):
    0  CLEAN or IN SYNC   -> `alembic upgrade head` is safe as-is
    2  UNSTAMPED, matches head -> run `alembic stamp head` first (see runbook)
    3  MANUAL REVIEW       -> do not run anything automatically
    1  error (could not connect / inspect)
"""
import os
import re
import sys

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
ALEMBIC_INI = os.path.join(REPO_ROOT, "alembic.ini")

# Matches `op.create_table('name'` and `op.create_table(\n    "name"` (name may
# sit on the next line), so it captures every table the chain would try to
# create — the exact surface that raises DuplicateTable on an unstamped DB.
_CREATE_TABLE_RE = re.compile(r"op\.create_table\(\s*['\"]([A-Za-z0-9_]+)['\"]")
_DROP_TABLE_RE = re.compile(r"op\.drop_table\(\s*['\"]([A-Za-z0-9_]+)['\"]")


def _normalize_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def _load_script() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(ALEMBIC_INI))


def _upgrade_body(src: str) -> str:
    """Return just the text of the migration's upgrade() function.

    We only care about forward (upgrade) operations: a table created in
    upgrade() exists at head; a drop_table in a *downgrade()* must be ignored
    (otherwise every table that its own downgrade drops would cancel out).
    """
    if "def upgrade" not in src:
        return ""
    body = src.split("def upgrade", 1)[1]
    return body.split("def downgrade", 1)[0]


def _tables_created_by_migrations(script: ScriptDirectory):
    """From upgrade() bodies only: (tables created forward, tables dropped forward).

    ``created - dropped`` is the set of tables expected to exist at head.
    ``created`` alone is the DuplicateTable "crash surface" for an upgrade that
    replays from base.
    """
    created, dropped = set(), set()
    for rev in script.walk_revisions():
        try:
            with open(rev.path, "r", encoding="utf-8") as fh:
                src = fh.read()
        except OSError:
            continue
        up = _upgrade_body(src)
        created.update(_CREATE_TABLE_RE.findall(up))
        dropped.update(_DROP_TABLE_RE.findall(up))
    return created, dropped


def _read_stamp(engine, existing_tables):
    """Return list of revisions in alembic_version (empty if none / no table)."""
    if "alembic_version" not in existing_tables:
        return None  # table absent
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
    return [r[0] for r in rows]


def classify(
    *,
    stamp,
    single_valid_stamp: bool,
    stamped_is_ancestor: bool,
    pending_count: int,
    present_count: int,
    missing,
    conflicts_count: int,
):
    """Pure decision function -> (verdict, exit_code, recommendation).

    ``stamp`` is None (no alembic_version table), [] (table present but empty),
    or a list of stamped revisions. Kept side-effect-free so it can be unit
    tested with synthetic facts (see --self-test).
    """
    has_rows = bool(stamp)

    if single_valid_stamp and stamped_is_ancestor:
        if pending_count == 0:
            verdict = "IN SYNC (already at head)"
            rec = "`alembic upgrade head` is a no-op. SAFE to deploy the entrypoint."
            if missing:
                rec += (f"\n  WARNING: stamped at head but {len(missing)} expected "
                        f"table(s) are missing — investigate drift before relying on it.")
            return verdict, 0, rec
        verdict = f"IN SYNC (behind head by {pending_count} revision(s))"
        rec = ("`alembic upgrade head` will apply the pending migrations. SAFE to "
               "deploy the entrypoint (it does exactly this).")
        return verdict, 0, rec

    if has_rows:
        # A stamp exists but is not a single known ancestor of head.
        verdict = "MANUAL REVIEW (alembic_version is unknown / multiple / off-chain)"
        rec = ("The stamp does not resolve to a single known revision on the path to "
               "head. Do NOT auto-run upgrade. Reconcile migration history manually.")
        return verdict, 3, rec

    # No usable stamp (table absent, or present-but-empty).
    if present_count == 0:
        verdict = "CLEAN (no migration tables present yet)"
        rec = ("Fresh database. `alembic upgrade head` will build the full schema "
               "from base. SAFE to deploy the entrypoint.")
        return verdict, 0, rec
    if not missing:
        verdict = "UNSTAMPED, SCHEMA MATCHES HEAD"
        rec = ("Tables exist (built by create_all) but the DB is not stamped. "
               "`alembic upgrade head` WOULD CRASH with DuplicateTable. Run "
               "`alembic stamp head` ONCE first (see runbook), then the entrypoint "
               "is safe.")
        return verdict, 2, rec
    verdict = "UNSTAMPED and schema does NOT cleanly match head"
    rec = ("Some migration tables exist and some are missing, with no valid stamp. "
           "Do NOT auto-run anything. Manual review required "
           f"(missing: {', '.join(missing) or 'none'}; "
           f"already-present conflicts: {conflicts_count}).")
    return verdict, 3, rec


def _self_test() -> int:
    """Deterministic check of every classify() branch (no DB needed)."""
    cases = [
        # (kwargs, expected_code, label)
        (dict(stamp=["head"], single_valid_stamp=True, stamped_is_ancestor=True,
              pending_count=0, present_count=37, missing=[], conflicts_count=37), 0,
         "IN SYNC at head"),
        (dict(stamp=["old"], single_valid_stamp=True, stamped_is_ancestor=True,
              pending_count=3, present_count=30, missing=["x"], conflicts_count=30), 0,
         "IN SYNC behind head"),
        (dict(stamp=["weird"], single_valid_stamp=False, stamped_is_ancestor=False,
              pending_count=0, present_count=37, missing=[], conflicts_count=37), 3,
         "MANUAL: unknown stamp"),
        (dict(stamp=["a", "b"], single_valid_stamp=False, stamped_is_ancestor=False,
              pending_count=0, present_count=37, missing=[], conflicts_count=37), 3,
         "MANUAL: multiple heads"),
        (dict(stamp=None, single_valid_stamp=False, stamped_is_ancestor=False,
              pending_count=0, present_count=0, missing=["all"], conflicts_count=0), 0,
         "CLEAN empty DB"),
        (dict(stamp=None, single_valid_stamp=False, stamped_is_ancestor=False,
              pending_count=0, present_count=37, missing=[], conflicts_count=37), 2,
         "UNSTAMPED matches head"),
        (dict(stamp=[], single_valid_stamp=False, stamped_is_ancestor=False,
              pending_count=0, present_count=37, missing=[], conflicts_count=37), 2,
         "UNSTAMPED (empty version table) matches head"),
        (dict(stamp=None, single_valid_stamp=False, stamped_is_ancestor=False,
              pending_count=0, present_count=35, missing=["audit_module_logs"],
              conflicts_count=35), 3,
         "UNSTAMPED partial (create_all only)"),
    ]
    ok = True
    for kwargs, expected, label in cases:
        verdict, code, _ = classify(**kwargs)
        status = "PASS" if code == expected else "FAIL"
        if code != expected:
            ok = False
        print(f"  [{status}] {label:40} -> code={code} ({verdict})")
    print("self-test:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return _self_test()
    url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: provide a DATABASE_URL (env var or first argument).")
        return 1
    url = _normalize_url(url)
    safe_display = re.sub(r"//([^:/@]+):[^@]*@", r"//\1:***@", url)

    print("=" * 72)
    print("Alembic stamp-safety check (READ-ONLY — makes no changes)")
    print("=" * 72)
    print(f"Target DB : {safe_display}")

    script = _load_script()
    head = script.get_current_head()
    known_revs = {r.revision for r in script.walk_revisions()}
    head_ancestors = {r.revision for r in script.iterate_revisions(head, "base")}
    created, dropped = _tables_created_by_migrations(script)
    expected_at_head = created - dropped
    print(f"Repo head : {head}  (chain has {len(known_revs)} revisions)")

    try:
        engine = create_engine(url)
        insp = inspect(engine)
        existing = set(insp.get_table_names())
    except Exception as exc:  # noqa: BLE001 - report any connection/inspect failure
        print(f"\nERROR: could not connect/inspect target DB: {exc}")
        return 1

    stamp = _read_stamp(engine, existing)

    present = sorted(expected_at_head & existing)
    missing = sorted(expected_at_head - existing)
    conflicts = sorted(created & existing)  # tables an upgrade-from-base would re-create

    print("\n--- Facts ---------------------------------------------------------")
    print(f"alembic_version table exists : {'yes' if stamp is not None else 'no'}")
    if stamp is not None:
        print(f"stamped revision(s)          : {stamp or '(table present but EMPTY)'}")
    print(f"migration-created tables      : {len(expected_at_head)} expected at head")
    print(f"  present in target DB        : {len(present)}")
    print(f"  missing from target DB      : {len(missing)}")
    if missing:
        print(f"    missing -> {', '.join(missing)}")

    # ---- Stamp validity / ancestry ----
    stamped_rev = stamp[0] if stamp else None
    single_valid_stamp = (
        stamp is not None and len(stamp) == 1 and stamped_rev in known_revs
    )
    stamped_is_ancestor = bool(single_valid_stamp and stamped_rev in head_ancestors)
    pending_count = 0
    if single_valid_stamp:
        s_ancestors = {r.revision for r in script.iterate_revisions(stamped_rev, "base")}
        pending_count = len(head_ancestors - s_ancestors)
        print(f"stamp is ancestor of head    : {'yes' if stamped_is_ancestor else 'NO'}")
        print(f"pending revisions to apply   : {pending_count}")
    if stamped_rev is not None and stamped_rev not in known_revs:
        print(f"  NOTE: stamped revision {stamped_rev!r} is NOT in this repo's chain")

    # ---- Classification ----
    print("\n--- Classification ------------------------------------------------")
    verdict, code, rec = classify(
        stamp=stamp,
        single_valid_stamp=single_valid_stamp,
        stamped_is_ancestor=stamped_is_ancestor,
        pending_count=pending_count,
        present_count=len(present),
        missing=missing,
        conflicts_count=len(conflicts),
    )

    print(f"  VERDICT   : {verdict}")
    print(f"  RECOMMEND : {rec}")
    print("\nNOTE: this check is table-granularity only. It does NOT verify column-"
          "level drift (e.g. widened varchars, added columns). A create_all DB has "
          "current model columns, but migration-only column changes are not proven "
          "here — see project memory 'alembic-createall-drift'.")
    print("=" * 72)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
