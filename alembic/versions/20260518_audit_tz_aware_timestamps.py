"""make audit-related timestamps timezone-aware

Revision ID: 20260518_audit_tz
Revises: c9f1e2d3a4b5, f9a3c7e8d2b1
Create Date: 2026-05-18

Converts DateTime columns on audit / log tables from naive to timezone-aware
(TIMESTAMP WITH TIME ZONE). Also merges the two existing heads.

Affected tables/columns:
  - login_logs.timestamp
  - asset_logs.timestamp
  - asset_requirement_logs.timestamp
  - audit_logs.timestamp
  - hardening_logs.timestamp
  - discovery_audit_logs.timestamp
  - discovery_scans.started_at, completed_at, created_at, updated_at
  - discovered_hosts.discovered_at, updated_at, approved_at
  - discovery_applications.applied_at

Existing naive values are interpreted as UTC.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260518_audit_tz"
down_revision: Union[str, Sequence[str], None] = ("c9f1e2d3a4b5", "f9a3c7e8d2b1")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TIMESTAMP_COLUMNS = [
    ("login_logs", "timestamp", False),
    ("asset_logs", "timestamp", True),
    ("asset_requirement_logs", "timestamp", True),
    ("audit_logs", "timestamp", False),
    ("hardening_logs", "timestamp", True),
    ("discovery_audit_logs", "timestamp", True),
    ("discovery_scans", "started_at", False),
    ("discovery_scans", "completed_at", True),
    ("discovery_scans", "created_at", True),
    ("discovery_scans", "updated_at", True),
    ("discovered_hosts", "discovered_at", True),
    ("discovered_hosts", "updated_at", True),
    ("discovered_hosts", "approved_at", True),
    ("discovery_applications", "applied_at", True),
]


def _is_postgres() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    """Convert naive DateTime columns to timezone-aware (UTC)."""
    if not _is_postgres():
        # SQLite stores ISO strings — no column-type change required.
        # New rows written from the ORM use timezone.utc; existing rows
        # remain naive ISO and are interpreted as UTC by the application.
        return

    for table, column, nullable in _TIMESTAMP_COLUMNS:
        op.execute(
            f'ALTER TABLE {table} '
            f'ALTER COLUMN "{column}" '
            f'TYPE TIMESTAMP WITH TIME ZONE '
            f'USING "{column}" AT TIME ZONE \'UTC\''
        )


def downgrade() -> None:
    """Revert to naive DateTime columns (drops timezone info, stores UTC)."""
    if not _is_postgres():
        return

    for table, column, nullable in _TIMESTAMP_COLUMNS:
        op.execute(
            f'ALTER TABLE {table} '
            f'ALTER COLUMN "{column}" '
            f'TYPE TIMESTAMP WITHOUT TIME ZONE '
            f'USING ("{column}" AT TIME ZONE \'UTC\')'
        )
