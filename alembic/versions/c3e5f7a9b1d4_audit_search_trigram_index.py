"""audit_logs: trigram index for the audit trail's text search

Revision ID: c3e5f7a9b1d4
Revises: b2c4d6e8f0a1
Create Date: 2026-10-11

The audit trail's search box matches text anywhere in the action, user, module and detail of an
event (ILIKE '%text%'). Without an index that reads every row: about 1.5 s per search at a million
events. A pg_trgm GIN index over the four fields joined (app/modules/audit_trail.py SEARCH_TEXT,
the same expression) answers the same searches from the index.

pg_trgm ships with PostgreSQL (contrib) and is a trusted extension, so the database owner may
create it. Where it cannot be created (no privilege, contrib not installed) the index is skipped
with a warning and search keeps working, only slower; running the migrations again later (or
creating the extension by hand and re-running this revision) adds it.

The extension lives in its own schema, ngcorion_ext, not in public: a restore swaps the public
schema for a staging one and moves public's extensions along, which needs ownership of the
extension's functions - and a trusted extension's functions belong to the superuser, not to the
database owner NGCorion connects as (app/modules/sysbackup/dbdump.py swap). The operator class is
named with that schema, since a restore runs the migrations with only its staging schema on the
search_path. An installation where pg_trgm already exists keeps it where it is.
"""
import warnings
from typing import Sequence, Union

from alembic import op

revision: str = "c3e5f7a9b1d4"
down_revision: Union[str, Sequence[str], None] = "b2c4d6e8f0a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Must stay identical to SEARCH_TEXT in app/modules/audit_trail.py, or the planner cannot use it.
SEARCH_TEXT = ("coalesce(action, '') || E'\\n' || coalesce(username, '') || E'\\n' || "
               "coalesce(module, '') || E'\\n' || coalesce(detail, '')")


def upgrade() -> None:
    bind = op.get_bind()
    try:
        with bind.begin_nested():
            bind.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS ngcorion_ext")
            bind.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA ngcorion_ext")
    except Exception as exc:  # noqa: BLE001 - any failure here only means "no index"
        warnings.warn(f"pg_trgm is not available ({exc.__class__.__name__}); the audit trail search "
                      "works without its index, only slower", stacklevel=1)
        return
    schema = bind.exec_driver_sql(
        "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace "
        "WHERE e.extname = 'pg_trgm'").scalar()
    bind.exec_driver_sql(
        f'CREATE INDEX IF NOT EXISTS ix_audit_logs_search_trgm ON audit_logs '
        f'USING gin (({SEARCH_TEXT}) "{schema}".gin_trgm_ops)')


def downgrade() -> None:
    # The extension stays: other objects may use it.
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_search_trgm")
