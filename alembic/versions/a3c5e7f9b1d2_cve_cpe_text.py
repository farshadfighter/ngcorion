"""CVE CPE criteria: unbounded text

The CPE 2.3 standard puts no limit on a vendor, product or version, and NVD has criteria longer
than the columns (long firmware versions and product names), which failed a whole CVE update.

Revision ID: a3c5e7f9b1d2
Revises: e8a0c2d4f6b9
Create Date: 2026-10-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a3c5e7f9b1d2"
down_revision: Union[str, Sequence[str], None] = "e8a0c2d4f6b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMNS = (("vendor", 120, False), ("product", 160, False), ("version", 80, True), ("start_incl", 80, True),
           ("start_excl", 80, True), ("end_incl", 80, True), ("end_excl", 80, True))


def upgrade() -> None:
    for name, _, nullable in COLUMNS:
        op.alter_column("cve_cpe_matches", name, type_=sa.Text(), existing_nullable=nullable)


def downgrade() -> None:
    # Longer values are cut to the old width; they cannot match an asset's version anyway.
    for name, width, nullable in COLUMNS:
        op.execute(f"UPDATE cve_cpe_matches SET {name} = LEFT({name}, {width}) WHERE LENGTH({name}) > {width}")
        op.alter_column("cve_cpe_matches", name, type_=sa.String(width), existing_nullable=nullable)
