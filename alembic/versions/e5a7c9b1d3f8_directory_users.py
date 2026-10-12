"""users: sign-in through Active Directory / LDAP (auth_source, external_dn, directory flags)

Revision ID: e5a7c9b1d3f8
Revises: d4f6a8c0e2b6
Create Date: 2026-10-12
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e5a7c9b1d3f8"
down_revision: Union[str, Sequence[str], None] = "d4f6a8c0e2b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("auth_source", sa.String(10), nullable=False, server_default="local"))
    op.add_column("users", sa.Column("external_dn", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("disabled_by_directory", sa.Boolean(), nullable=False,
                                     server_default=sa.false()))
    op.add_column("users", sa.Column("directory_synced_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "directory_synced_at")
    op.drop_column("users", "disabled_by_directory")
    op.drop_column("users", "external_dn")
    op.drop_column("users", "auth_source")
