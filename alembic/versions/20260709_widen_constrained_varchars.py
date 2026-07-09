"""widen undersized varchar columns (schema/value length audit)

Revision ID: 20260709_widen
Revises: 20260628_vdom
Create Date: 2026-07-09

A schema audit of every String(N) column against the values the code can
write found one live overflow and a family of near-limit columns:

* hardening_actions.action_type is VARCHAR(10) but the manual "View Fix"
  execution path writes 'manual-execute' (14 chars) — every manual execution
  failed with StringDataRightTruncation (500).
* check_number is VARCHAR(20) in hardening_actions / audit_results /
  audit_checks, while the longest CIS check id already in the codebase is
  19 chars ('LNX-RHEL-L1-5.3.1.1'); one more numbering level overflows it.
* The status columns of hardening_actions and audit_sessions are widened to
  VARCHAR(30) alongside action_type so all type/status fields share the same
  safe size.

Widening VARCHARs is metadata-only in PostgreSQL (no table rewrite).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '20260709_widen'
down_revision: Union[str, Sequence[str], None] = '20260628_vdom'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, column, old_size, new_size, nullable)
_WIDENED = [
    ("hardening_actions", "action_type",  10, 30, False),
    ("hardening_actions", "status",       20, 30, False),
    ("hardening_actions", "check_number", 20, 50, False),
    ("audit_results",     "check_number", 20, 50, True),
    ("audit_checks",      "check_number", 20, 50, False),
    ("audit_sessions",    "status",       20, 30, True),
]


def upgrade() -> None:
    for table, column, old, new, nullable in _WIDENED:
        op.alter_column(
            table, column,
            existing_type=sa.String(length=old),
            type_=sa.String(length=new),
            existing_nullable=nullable,
        )


def downgrade() -> None:
    # Narrowing fails if longer values (e.g. action_type='manual-execute')
    # have been written since the upgrade — that data loss is intentional
    # to refuse silently truncating history.
    for table, column, old, new, nullable in reversed(_WIDENED):
        op.alter_column(
            table, column,
            existing_type=sa.String(length=new),
            type_=sa.String(length=old),
            existing_nullable=nullable,
        )
