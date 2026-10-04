"""Active Directory audits: devicetype enum value

Revision ID: a7d1c3e5b9f2
Revises: f5c2a8e91b37
Create Date: 2026-10-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'a7d1c3e5b9f2'
down_revision: Union[str, Sequence[str], None] = 'f5c2a8e91b37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'ACTIVE_DIRECTORY'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value; audit rows of this type would
    # have to be removed and the type rebuilt. Left as a no-op, like the
    # earlier devicetype additions.
    pass
