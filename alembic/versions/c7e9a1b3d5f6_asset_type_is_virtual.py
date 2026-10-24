"""Asset types: physical or virtual

A virtual type (virtual server, VM, virtual appliance) runs on another asset: each asset of it names the
physical server it runs on. Types whose name already said so (VM, Virtual ...) start as virtual.

Revision ID: c7e9a1b3d5f6
Revises: b5d7f9a1c3e4
Create Date: 2026-10-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c7e9a1b3d5f6"
down_revision: Union[str, Sequence[str], None] = "b5d7f9a1c3e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_types", sa.Column(
        "is_virtual", sa.Boolean(), nullable=False, server_default=sa.false(),
        comment="Virtual: its assets run on a physical server"))
    op.execute(r"UPDATE asset_types SET is_virtual = true "
               r"WHERE type_name ~* '(^|[^a-z])(vm|virtual)([^a-z]|$)'")


def downgrade() -> None:
    op.drop_column("asset_types", "is_virtual")
