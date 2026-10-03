"""distribution security advisories: affected ranges per package and release, feed state

Revision ID: f5c2a8e91b37
Revises: e3a7c90d1f52
Create Date: 2026-10-06 09:00:00.000000

See app/models/advisory.py. Shown under the CVE permission, so no new
permission module.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f5c2a8e91b37"
down_revision: Union[str, Sequence[str], None] = "e3a7c90d1f52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Advisories name the source package's version; a binary can carry its own.
    op.add_column("software_items", sa.Column("source_version", sa.String(160), nullable=True))
    op.create_table(
        "distro_vulns",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("release", sa.String(24), nullable=False),
        sa.Column("stream", sa.String(80), nullable=False),
        sa.Column("package", sa.String(200), nullable=False),
        sa.Column("record_id", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("introduced", sa.String(160), nullable=True),
        sa.Column("fixed", sa.String(160), nullable=True),
        sa.Column("last_affected", sa.String(160), nullable=True),
        sa.Column("cves", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(12), nullable=True),
        sa.Column("availability", sa.String(10), nullable=False, server_default="standard"),
        sa.Column("title", sa.String(300), nullable=True),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.Column("modified", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_distro_vulns_release_package", "distro_vulns", ["release", "package"])
    op.create_index("ix_distro_vulns_record", "distro_vulns", ["record_id"])
    op.create_table(
        "distro_feeds",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("release", sa.String(24), nullable=False, unique=True),
        sa.Column("rows", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("watermark", sa.DateTime(), nullable=True),
        sa.Column("loaded_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(12), nullable=True),
        sa.Column("last_changes", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("distro_feeds")
    op.drop_index("ix_distro_vulns_record", table_name="distro_vulns")
    op.drop_index("ix_distro_vulns_release_package", table_name="distro_vulns")
    op.drop_table("distro_vulns")
    op.drop_column("software_items", "source_version")
