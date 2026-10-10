"""Idle session timeout (user_sessions) and an append-only audit trail

* user_sessions: one row per access token, with when it was last used
  (app/models/user_session.py, app/core/sessions.py).
* audit_logs becomes append-only: a trigger refuses UPDATE and DELETE.
  Two exceptions, both needed by the product itself:
    - the foreign key's ON DELETE SET NULL when a user account is deleted
      (the entry stays, it just no longer points at the account);
    - a connection that declares maintenance with the setting
      ngcorion.audit_maintenance = on, which only the backup/restore engine
      does (a restore replaces the whole database, audit trail included).
  Anyone with direct database rights can of course still change the table;
  the trigger keeps every application path - and mistakes - from doing so.

Revision ID: a1d3f5b7c9e2
Revises: f9c2d4e6a8b0
Create Date: 2026-10-11 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a1d3f5b7c9e2'
down_revision: Union[str, Sequence[str], None] = 'f9c2d4e6a8b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

GUARD = """
CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$
BEGIN
    IF current_setting('ngcorion.audit_maintenance', true) = 'on' THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.user_id IS NULL AND OLD.user_id IS NOT NULL
       AND (to_jsonb(NEW) - 'user_id') = (to_jsonb(OLD) - 'user_id') THEN
        RETURN NEW;  -- ON DELETE SET NULL of the user account
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_logs_no_change ON audit_logs;
CREATE TRIGGER audit_logs_no_change BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
"""


def upgrade() -> None:
    # The app's create_all may have made the table already (a database that was
    # started before it was migrated); the trigger is (re)created either way.
    if sa.inspect(op.get_bind()).has_table("user_sessions"):
        op.execute(GUARD)
        return
    op.create_table(
        "user_sessions",
        sa.Column("jti", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])
    op.execute(GUARD)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_change ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_append_only()")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
