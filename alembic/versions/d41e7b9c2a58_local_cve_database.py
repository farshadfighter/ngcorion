"""local CVE database (replaces cve_records)

Revision ID: d41e7b9c2a58
Revises: c3d9f2a7e614
Create Date: 2026-10-01 05:00:00.000000

The old cve_records table held a 21-entry curated seed matched by keyword;
it is replaced by a full local copy of NVD matched by CPE. Its rows are not
migrated: everything it held is in NVD and arrives with the first load.
"""
from alembic import op
import sqlalchemy as sa


revision = "d41e7b9c2a58"
down_revision = "c3d9f2a7e614"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_entries",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(32), nullable=True),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_version", sa.String(8), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("cwe", sa.String(200), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_added", sa.Date(), nullable=True),
        sa.Column("kev_due", sa.Date(), nullable=True),
        sa.Column("kev_ransomware", sa.String(16), nullable=True),
        sa.Column("kev_action", sa.Text(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_cve_entries_last_modified", "cve_entries", ["last_modified"])
    op.create_index("ix_cve_entries_severity", "cve_entries", ["severity"])
    op.create_index("ix_cve_entries_kev", "cve_entries", ["kev"])

    op.create_table(
        "cve_cpe_matches",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(32), sa.ForeignKey("cve_entries.cve_id", ondelete="CASCADE"), nullable=False),
        sa.Column("part", sa.String(1), nullable=True),
        sa.Column("vendor", sa.String(120), nullable=False),
        sa.Column("product", sa.String(160), nullable=False),
        sa.Column("version", sa.String(80), nullable=True),
        sa.Column("start_incl", sa.String(80), nullable=True),
        sa.Column("start_excl", sa.String(80), nullable=True),
        sa.Column("end_incl", sa.String(80), nullable=True),
        sa.Column("end_excl", sa.String(80), nullable=True),
    )
    op.create_index("ix_cve_cpe_matches_cve_id", "cve_cpe_matches", ["cve_id"])
    op.create_index("ix_cve_cpe_matches_vendor_product", "cve_cpe_matches", ["vendor", "product"])

    op.create_table(
        "asset_software",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor", sa.String(120), nullable=False),
        sa.Column("product", sa.String(160), nullable=False),
        sa.Column("version", sa.String(80), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("asset_id", "vendor", "product", "version", name="uq_asset_software"),
    )
    op.create_index("ix_asset_software_asset_id", "asset_software", ["asset_id"])

    op.create_table(
        "cve_update_jobs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("progress", sa.JSON(), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("file_name", sa.String(255), nullable=True),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_cve_update_jobs_status", "cve_update_jobs", ["status"])

    op.create_table(
        "cve_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "cve_trusted_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("public_key", sa.String(100), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.drop_index("ix_cve_records_product_keyword", table_name="cve_records")
    op.drop_index("ix_cve_records_cve_id", table_name="cve_records")
    op.drop_index("ix_cve_records_id", table_name="cve_records")
    op.drop_table("cve_records")


def downgrade() -> None:
    op.create_table(
        "cve_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column("vendor", sa.String(length=100), nullable=False),
        sa.Column("product", sa.String(length=100), nullable=False),
        sa.Column("product_keyword", sa.String(length=100), nullable=False),
        sa.Column("affected_version_min", sa.String(length=50), nullable=True),
        sa.Column("affected_version_max", sa.String(length=50), nullable=True),
        sa.Column("fixed_version", sa.String(length=50), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("reference_url", sa.String(length=500), nullable=True),
        sa.Column("published_date", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id", "product_keyword", "affected_version_min", "affected_version_max",
                            name="uq_cve_records_branch"),
    )
    op.create_index("ix_cve_records_id", "cve_records", ["id"], unique=False)
    op.create_index("ix_cve_records_cve_id", "cve_records", ["cve_id"], unique=False)
    op.create_index("ix_cve_records_product_keyword", "cve_records", ["product_keyword"], unique=False)
    for table in ("cve_trusted_keys", "cve_settings", "cve_update_jobs", "asset_software", "cve_cpe_matches", "cve_entries"):
        op.drop_table(table)
