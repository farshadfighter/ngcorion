"""Assets: last hardening date, last audit date from the audits, no blank serial numbers

- last_hardening_date: the day of the last successful hardening change, kept by NGCorion
  (app/models/asset_dates.py); filled from the hardening that already ran.
- last_audit_date: moved forward to the last completed audit of the asset, which until now never
  set it.
- serial_number "" -> NULL: the column is unique, so a second asset saved without a serial collided
  with the first ("" stored by the edit form).

Revision ID: b5d7f9a1c3e4
Revises: a3c5e7f9b1d2
Create Date: 2026-10-20
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b5d7f9a1c3e4"
down_revision: Union[str, Sequence[str], None] = "a3c5e7f9b1d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_inventory", sa.Column(
        "last_hardening_date", sa.Date(), nullable=True,
        comment="Date of the last successful hardening change (app/models/asset_dates.py)"))
    op.execute("""
        UPDATE asset_inventory a SET last_hardening_date = h.day
        FROM (SELECT asset_id, max(coalesce(completed_at, executed_at))::date AS day
              FROM hardening_actions
              WHERE status = 'success' AND action_type <> 'preview'
              GROUP BY asset_id) h
        WHERE h.asset_id = a.id AND h.day IS NOT NULL
    """)
    op.execute("""
        UPDATE asset_inventory a SET last_audit_date = s.day
        FROM (SELECT asset_id, max(coalesce(completed_at, started_at))::date AS day
              FROM audit_sessions
              WHERE status = 'completed' AND asset_id IS NOT NULL
              GROUP BY asset_id) s
        WHERE s.asset_id = a.id AND s.day IS NOT NULL
          AND (a.last_audit_date IS NULL OR a.last_audit_date < s.day)
    """)
    op.execute("UPDATE asset_inventory SET serial_number = NULL WHERE trim(serial_number) = ''")


def downgrade() -> None:
    op.drop_column("asset_inventory", "last_hardening_date")
