"""
Database half of the self-backup.

Export: every table of the public schema is copied out in one REPEATABLE READ
snapshot, so the backup is consistent even while the product keeps running.

Restore never touches the live schema until the very end. The backup is
loaded into a staging schema built by the product's own migrations at the
backup's revision, checked, migrated to the current version, and only then
swapped in for public with two renames. Anything that fails before the swap
just drops the staging schema; the running system never noticed.
"""
import logging
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import psycopg
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]

# What each optional part of a backup holds. Every other table is "essential".
CATEGORY_TABLES = {
    "cve": ("cve_entries", "cve_cpe_matches"),
    "noc_history": ("asset_metric_samples", "asset_metric_rollups"),
    "reports": ("report_files",),
}
CATEGORIES = ("essential",) + tuple(CATEGORY_TABLES)
# The catalog of this server's own backups describes files on this server's
# disk: never exported, and kept from the running system on restore.
LOCAL_TABLES = ("system_backups", "system_restores")
# Self-backup configuration: kept from the running system when it has any,
# taken from the backup on a fresh server.
ADOPT_TABLES = ("backup_destinations",)
SKIP_TABLES = ("alembic_version",) + LOCAL_TABLES
SETTINGS_SECTION = "system_backup"

STAGING = "ngrestore"
TEST_STAGING = "ngtest"


class RestoreError(Exception):
    pass


def category_of(table: str) -> str:
    for cat, tables in CATEGORY_TABLES.items():
        if table in tables:
            return cat
    return "essential"


def dsn() -> str:
    url = make_url(settings.DATABASE_URL).set(drivername="postgresql")
    return url.render_as_string(hide_password=False)


def connect(**kw) -> psycopg.Connection:
    return psycopg.connect(dsn(), **kw)


def _sa_url() -> str:
    url = settings.DATABASE_URL
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _q(*names: str) -> sql.Composable:
    return sql.SQL(".").join(sql.Identifier(n) for n in names)


def _cols(columns: Iterable[str]) -> sql.Composable:
    return sql.SQL(", ").join(sql.Identifier(c) for c in columns)


# ── catalog queries ──────────────────────────────────────────────────────

def tables(cur, schema: str) -> List[str]:
    cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relkind IN ('r', 'p') AND NOT c.relispartition
                   ORDER BY c.relname""", (schema,))
    return [r[0] for r in cur.fetchall()]


def columns(cur, schema: str, table: str) -> List[str]:
    cur.execute("""SELECT a.attname FROM pg_attribute a
                   JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0
                     AND NOT a.attisdropped AND a.attgenerated = ''
                   ORDER BY a.attnum""", (schema, table))
    return [r[0] for r in cur.fetchall()]


def schema_exists(cur, schema: str) -> bool:
    cur.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (schema,))
    return cur.fetchone() is not None


def revision(cur, schema: str = "public") -> Optional[str]:
    try:
        cur.execute(sql.SQL("SELECT version_num FROM {}").format(_q(schema, "alembic_version")))
        row = cur.fetchone()
        return row[0] if row else None
    except psycopg.errors.UndefinedTable:
        return None


def owned_sequences(cur, schema: str) -> List[Tuple[str, str, str]]:
    """(sequence, table, column) for every sequence a column owns."""
    cur.execute("""SELECT s.relname, t.relname, a.attname FROM pg_class s
                   JOIN pg_namespace n ON n.oid = s.relnamespace
                   JOIN pg_depend d ON d.objid = s.oid AND d.classid = 'pg_class'::regclass
                        AND d.deptype IN ('a', 'i')
                   JOIN pg_class t ON t.oid = d.refobjid
                   JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid
                   WHERE s.relkind = 'S' AND n.nspname = %s""", (schema,))
    return cur.fetchall()


def sequences(cur, schema: str) -> List[str]:
    cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relkind = 'S'""", (schema,))
    return [r[0] for r in cur.fetchall()]


# ── export ────────────────────────────────────────────────────────────────

def snapshot(conn: psycopg.Connection, categories: Iterable[str]) -> dict:
    """Plan of the export, read inside the caller's snapshot transaction:
    revision, tables with columns and row counts, sequence positions."""
    wanted = set(categories)
    cur = conn.cursor()
    rev = revision(cur)
    if rev is None:
        raise RestoreError("the database has no migration revision")
    plan = {"revision": rev, "tables": {}, "sequences": {}}
    for t in tables(cur, "public"):
        if t in SKIP_TABLES:
            continue
        cat = category_of(t)
        if cat not in wanted:
            continue
        cur.execute(sql.SQL("SELECT count(*) FROM {}").format(_q("public", t)))
        rows = cur.fetchone()[0]
        plan["tables"][t] = {"category": cat, "columns": columns(cur, "public", t), "rows": rows}
    for s in sequences(cur, "public"):
        cur.execute(sql.SQL("SELECT last_value, is_called FROM {}").format(_q("public", s)))
        value, called = cur.fetchone()
        plan["sequences"][s] = {"value": int(value), "called": bool(called)}
    return plan


def begin_snapshot(conn: psycopg.Connection) -> None:
    conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")


def copy_out(conn: psycopg.Connection, table: str, cols: List[str]) -> Iterator[bytes]:
    cur = conn.cursor()
    stmt = sql.SQL("COPY {} ({}) TO STDOUT").format(_q("public", table), _cols(cols))
    with cur.copy(stmt) as copy:
        for data in copy:
            yield bytes(data)


# ── staging schema ────────────────────────────────────────────────────────

def known_revision(rev: str) -> bool:
    from alembic.script import ScriptDirectory
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    try:
        return ScriptDirectory.from_config(cfg).get_revision(rev) is not None
    except Exception:
        return False


def head_revision() -> str:
    from alembic.script import ScriptDirectory
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    return ScriptDirectory.from_config(cfg).get_current_head()


def migrate(schema: str, rev: str) -> None:
    """Run the product's migrations inside `schema` up to `rev`."""
    from alembic import command
    from alembic.config import Config

    cfg = Config()          # no ini file: alembic must not reconfigure the app's logging
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    engine = create_engine(_sa_url(), poolclass=NullPool)
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql(f'SET search_path TO "{schema}"')
            conn.commit()
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, rev)
            conn.commit()
    finally:
        engine.dispose()


def model_tables() -> List[str]:
    from app.core.database import Base
    import app.models  # noqa: F401  (registers every table on Base)
    return list(Base.metadata.tables)


def create_missing(schema: str, names: Iterable[str]) -> List[str]:
    """Create tables the backup has but the migrations at its revision do
    not (tables the app creates at startup). Unknown tables are an error."""
    from app.core.database import Base
    import app.models  # noqa: F401
    engine = create_engine(_sa_url(), poolclass=NullPool)
    made = []
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql(f'SET search_path TO "{schema}"')
            existing = set(r[0] for r in conn.execute(text(
                "SELECT tablename FROM pg_tables WHERE schemaname = :s"), {"s": schema}))
            for name in names:
                if name in existing:
                    continue
                table = Base.metadata.tables.get(name)
                if table is None:
                    raise RestoreError(f"the backup has a table this version does not know: {name}")
                table.create(conn, checkfirst=True)
                made.append(name)
            conn.commit()
    finally:
        engine.dispose()
    return made


def reset_schema(cur, schema: str) -> None:
    cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
    cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))


def drop_schema(schema: str) -> None:
    with connect(autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))


def truncate_all(cur, schema: str) -> None:
    names = [t for t in tables(cur, schema) if t != "alembic_version"]
    if names:
        cur.execute(sql.SQL("TRUNCATE {} RESTART IDENTITY CASCADE").format(
            sql.SQL(", ").join(_q(schema, t) for t in names)))


def drop_foreign_keys(cur, schema: str) -> List[Tuple[str, str, str]]:
    cur.execute("""SELECT t.relname, c.conname, pg_get_constraintdef(c.oid)
                   FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
                   JOIN pg_namespace n ON n.oid = t.relnamespace
                   WHERE n.nspname = %s AND c.contype = 'f' ORDER BY t.relname, c.conname""", (schema,))
    fks = cur.fetchall()
    for table, name, _ in fks:
        cur.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}").format(_q(schema, table), sql.Identifier(name)))
    return fks


def add_foreign_keys(cur, schema: str, fks: List[Tuple[str, str, str]]) -> None:
    """Re-add without checking existing rows; validate_foreign_keys checks."""
    cur.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
    try:
        for table, name, definition in fks:
            # The definition names the referenced table without a schema; the
            # search_path above makes it resolve inside the staging schema.
            cur.execute(sql.SQL("ALTER TABLE {} ADD CONSTRAINT {} {} NOT VALID").format(
                _q(schema, table), sql.Identifier(name), sql.SQL(definition)))
    finally:
        cur.execute("SET search_path TO DEFAULT")


def copy_in(cur, schema: str, table: str, cols: List[str], blocks: Iterator[bytes]) -> None:
    stmt = sql.SQL("COPY {} ({}) FROM STDIN").format(_q(schema, table), _cols(cols))
    with cur.copy(stmt) as copy:
        for data in blocks:
            copy.write(data)


def count(cur, schema: str, table: str) -> int:
    cur.execute(sql.SQL("SELECT count(*) FROM {}").format(_q(schema, table)))
    return cur.fetchone()[0]


def carry_over(cur, schema: str, table: str, replace: bool = True) -> int:
    """Copy the running system's rows of `table` into the staging schema
    (columns both versions have). Foreign keys must be dropped meanwhile."""
    if table not in tables(cur, "public") or table not in tables(cur, schema):
        return 0
    common = [c for c in columns(cur, schema, table) if c in set(columns(cur, "public", table))]
    if not common:
        return 0
    if replace:
        cur.execute(sql.SQL("DELETE FROM {}").format(_q(schema, table)))
    cur.execute(sql.SQL("INSERT INTO {} ({}) SELECT {} FROM {}").format(
        _q(schema, table), _cols(common), _cols(common), _q("public", table)))
    return cur.rowcount


def carry_over_setting(cur, schema: str) -> bool:
    """Keep the running system's self-backup settings (its passphrase above
    all); a fresh server without any keeps the backup's."""
    from psycopg.types.json import Json
    cur.execute("SELECT config_json FROM public.system_config_settings WHERE section = %s", (SETTINGS_SECTION,))
    row = cur.fetchone()
    if row is None:
        return False
    target = _q(schema, "system_config_settings")
    cur.execute(sql.SQL("UPDATE {} SET config_json = %s, updated_by = NULL, updated_at = now() at time zone 'utc' "
                        "WHERE section = %s").format(target), (Json(row[0]), SETTINGS_SECTION))
    if cur.rowcount == 0:
        cur.execute(sql.SQL("INSERT INTO {} (id, section, config_json, created_at, updated_at) "
                            "SELECT coalesce(max(id), 0) + 1, %s, %s, now() at time zone 'utc', "
                            "now() at time zone 'utc' FROM {}").format(target, target),
                    (SETTINGS_SECTION, Json(row[0])))
    return True


def repair_orphans(cur, schema: str) -> Dict[str, int]:
    """Rows carried over from the running system may point at rows the
    backup does not have (history of an asset that did not exist then).
    Delete them, or clear the reference where the key says SET NULL."""
    cur.execute("""SELECT c.conname, t.relname, f.relname, c.confdeltype,
                          ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n, i)
                                JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.i),
                          ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY k(n, i)
                                JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n ORDER BY k.i)
                   FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
                   JOIN pg_class f ON f.oid = c.confrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                   WHERE n.nspname = %s AND c.contype = 'f' AND NOT c.convalidated""", (schema,))
    fixed = {}
    for name, child, parent, on_delete, ccols, pcols in cur.fetchall():
        not_null = sql.SQL(" AND ").join(sql.SQL("c.{} IS NOT NULL").format(sql.Identifier(x)) for x in ccols)
        match = sql.SQL(" AND ").join(sql.SQL("p.{} = c.{}").format(sql.Identifier(p), sql.Identifier(c))
                                      for c, p in zip(ccols, pcols))
        orphan = sql.SQL("{} AND NOT EXISTS (SELECT 1 FROM {} p WHERE {})").format(
            not_null, _q(schema, parent), match)
        if on_delete == "n":
            stmt = sql.SQL("UPDATE {} c SET {} WHERE {}").format(
                _q(schema, child),
                sql.SQL(", ").join(sql.SQL("{} = NULL").format(sql.Identifier(x)) for x in ccols), orphan)
        else:
            stmt = sql.SQL("DELETE FROM {} c WHERE {}").format(_q(schema, child), orphan)
        cur.execute(stmt)
        if cur.rowcount:
            fixed[f"{child}.{name}"] = cur.rowcount
        cur.execute(sql.SQL("ALTER TABLE {} VALIDATE CONSTRAINT {}").format(
            _q(schema, child), sql.Identifier(name)))
    return fixed


def validate_foreign_keys(cur, schema: str) -> None:
    cur.execute("""SELECT t.relname, c.conname FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
                   JOIN pg_namespace n ON n.oid = t.relnamespace
                   WHERE n.nspname = %s AND c.contype = 'f' AND NOT c.convalidated""", (schema,))
    for table, name in cur.fetchall():
        try:
            cur.execute(sql.SQL("ALTER TABLE {} VALIDATE CONSTRAINT {}").format(
                _q(schema, table), sql.Identifier(name)))
        except psycopg.errors.ForeignKeyViolation as exc:
            raise RestoreError(f"the backup is inconsistent: {table}.{name}") from exc


def set_sequences(cur, schema: str, recorded: Dict[str, dict]) -> None:
    """Every sequence continues after both the highest key in its table and
    the position recorded in the backup."""
    for seq, table, column in owned_sequences(cur, schema):
        cur.execute(sql.SQL("SELECT max({}) FROM {}").format(sql.Identifier(column), _q(schema, table)))
        top = cur.fetchone()[0]
        top = int(top) if isinstance(top, int) else 0
        rec = recorded.get(seq) or {}
        value = max(top, int(rec.get("value") or 0) if rec.get("called") else 0)
        if value > 0:
            cur.execute("SELECT setval(%s, %s, true)", (f'"{schema}"."{seq}"', value))
        else:
            cur.execute("SELECT setval(%s, 1, false)", (f'"{schema}"."{seq}"',))


# ── swap ──────────────────────────────────────────────────────────────────

def terminate_others(cur) -> int:
    """Disconnect every other session of this database user, so no one keeps
    plans bound to the old tables. Idle sessions that only hold an advisory
    lock (the background-task leader locks, the backup job lock) are spared:
    they touch no tables, and dropping them would hand a leader role around
    mid-restore."""
    cur.execute("""SELECT count(pg_terminate_backend(a.pid)) FROM pg_stat_activity a
                   WHERE a.datname = current_database() AND a.pid <> pg_backend_pid()
                     AND a.usename = current_user
                     AND NOT (a.state = 'idle' AND EXISTS (
                         SELECT 1 FROM pg_locks l WHERE l.pid = a.pid AND l.locktype = 'advisory' AND l.granted))""")
    return cur.fetchone()[0]


def _sync_local(cur, staging: str, names: Iterable[str]) -> None:
    """Copy the running system's rows of the server-local tables into the
    staging schema, as they are at this moment (the restore itself has been
    writing its progress there)."""
    names = [n for n in names if n in tables(cur, staging) and n in tables(cur, "public")]
    for name in reversed(names):
        cur.execute(sql.SQL("DELETE FROM {}").format(_q(staging, name)))
    for name in names:
        common = [c for c in columns(cur, staging, name) if c in set(columns(cur, "public", name))]
        cur.execute(sql.SQL("INSERT INTO {} ({}) SELECT {} FROM {}").format(
            _q(staging, name), _cols(common), _cols(common), _q("public", name)))
    for seq, table, column in owned_sequences(cur, staging):
        if table in names:
            cur.execute(sql.SQL("SELECT coalesce(max({}), 0) FROM {}").format(sql.Identifier(column),
                                                                             _q(staging, table)))
            top = cur.fetchone()[0]
            if top:
                cur.execute("SELECT setval(%s, %s, true)", (f'"{staging}"."{seq}"', top))


def swap(staging: str = STAGING, local_tables: Iterable[str] = LOCAL_TABLES) -> str:
    """Put the staging schema in place of public. Returns the old schema's
    new name; drop it with drop_schema once the restored system is checked."""
    old = "ngold_" + time.strftime("%Y%m%d%H%M%S")
    with connect(autocommit=True) as conn:
        cur = conn.cursor()
        cur.execute("SET lock_timeout = '20s'")
        terminate_others(cur)
        with conn.transaction():
            _sync_local(cur, staging, local_tables)
            cur.execute(sql.SQL("ALTER SCHEMA public RENAME TO {}").format(sql.Identifier(old)))
            cur.execute(sql.SQL("ALTER SCHEMA {} RENAME TO public").format(sql.Identifier(staging)))
            cur.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")
            cur.execute("""SELECT e.extname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
                           WHERE n.nspname = %s""", (old,))
            for (ext,) in cur.fetchall():
                cur.execute(sql.SQL("ALTER EXTENSION {} SET SCHEMA public").format(sql.Identifier(ext)))
        # Sessions opened between the terminate and the rename may still hold
        # plans bound to the old tables.
        terminate_others(cur)
    from app.core.database import engine
    engine.dispose()
    return old


def leftover_schemas() -> List[str]:
    with connect(autocommit=True) as conn:
        cur = conn.execute("""SELECT nspname FROM pg_namespace
                              WHERE nspname LIKE 'ngold\\_%%' OR nspname IN (%s, %s)""", (STAGING, TEST_STAGING))
        return [r[0] for r in cur.fetchall()]
