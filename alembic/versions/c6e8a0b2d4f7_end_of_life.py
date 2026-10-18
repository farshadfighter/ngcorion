"""End of life: downloaded / imported / own catalog products, end of support entered by hand

Revision ID: c6e8a0b2d4f7
Revises: b5d7f9a1c3e6
Create Date: 2026-10-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c6e8a0b2d4f7"
down_revision: Union[str, Sequence[str], None] = "b5d7f9a1c3e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "eol_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(60), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("link", sa.String(300), nullable=True),
        sa.Column("match_names", sa.JSON(), nullable=True),
        sa.Column("cycles", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "eol_asset_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(80), nullable=True),
        sa.Column("support_until", sa.Date(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_eol_asset_entries_asset_id", "eol_asset_entries", ["asset_id"])


def downgrade() -> None:
    op.drop_table("eol_asset_entries")
    op.drop_table("eol_products")
