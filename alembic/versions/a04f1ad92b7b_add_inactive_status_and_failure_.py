"""add INACTIVE to statusenum + consecutive_poll_failures to asset_snmp_status

Revision ID: a04f1ad92b7b
Revises: c8ed1dfbbf0d
Create Date: 2026-09-20 12:00:00.000000

Supports NOC-driven auto status: after several consecutive failed polls, an
SNMP-monitored asset's status is set to INACTIVE automatically (and back to
ACTIVE on the next successful poll) instead of requiring a manual edit.
consecutive_poll_failures tracks the streak so a single blip doesn't flip
status (flap-dampening).

The enum value is added in an autocommit block: PostgreSQL forbids using a
new enum value in the same transaction that added it, and older servers
forbid ALTER TYPE ... ADD VALUE inside a transaction entirely (same pattern
as c1e9a4f7b2d6 / 2184b555dc50 / c8ed1dfbbf0d for moduleenum).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a04f1ad92b7b'
down_revision: Union[str, Sequence[str], None] = 'c8ed1dfbbf0d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE statusenum ADD VALUE IF NOT EXISTS 'INACTIVE'")

    op.add_column(
        'asset_snmp_status',
        sa.Column('consecutive_poll_failures', sa.Integer(), nullable=False, server_default='0'),
    )


def downgrade() -> None:
    op.drop_column('asset_snmp_status', 'consecutive_poll_failures')
    # PostgreSQL cannot drop a value from an enum type - see c1e9a4f7b2d6's
    # downgrade for the full rationale. No-op; roll back in practice by
    # re-setting any INACTIVE asset_inventory.status rows to 'active' or
    # 'unknown' by hand.
