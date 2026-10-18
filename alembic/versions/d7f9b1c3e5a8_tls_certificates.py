"""TLS certificates: the TLS services of the assets with their certificate, the organisation's CAs

Revision ID: d7f9b1c3e5a8
Revises: c6e8a0b2d4f7
Create Date: 2026-10-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d7f9b1c3e5a8"
down_revision: Union[str, Sequence[str], None] = "c6e8a0b2d4f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tls_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("server_name", sa.String(255), nullable=True),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
        sa.Column("error", sa.String(300), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("subject", sa.String(500), nullable=True),
        sa.Column("issuer", sa.String(500), nullable=True),
        sa.Column("names", sa.JSON(), nullable=True),
        sa.Column("serial", sa.String(80), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=True),
        sa.Column("not_before", sa.DateTime(), nullable=True),
        sa.Column("not_after", sa.DateTime(), nullable=True),
        sa.Column("key_type", sa.String(10), nullable=True),
        sa.Column("key_bits", sa.Integer(), nullable=True),
        sa.Column("signature", sa.String(20), nullable=True),
        sa.Column("self_signed", sa.Boolean(), nullable=True),
        sa.Column("trusted", sa.Boolean(), nullable=True),
        sa.Column("trust_error", sa.String(200), nullable=True),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("old_protocols", sa.JSON(), nullable=True),
        sa.Column("chain", sa.JSON(), nullable=True),
        sa.Column("cert_changed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.UniqueConstraint("asset_id", "host", "port", name="uq_tls_endpoints_asset_host_port"),
    )
    op.create_index("ix_tls_endpoints_asset_id", "tls_endpoints", ["asset_id"])
    op.create_table(
        "tls_trusted_cas",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("pem", sa.Text(), nullable=False),
        sa.Column("not_after", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("tls_trusted_cas")
    op.drop_table("tls_endpoints")
