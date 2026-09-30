"""Add if_name/if_alias to asset_snmp_interfaces

Revision ID: 856a4b0ddefc
Revises: 602468fddd33
Create Date: 2026-09-30 00:00:00.000000

IF-MIB ifDescr alone is frequently blank (VLANs/aggregates/tunnels on
FortiGate) or unhelpful (a low-level driver name) - ifName and ifAlias
(IF-MIB ifXTable, RFC 2863) are the fields a human actually recognizes as
"the interface name", so they're collected and stored alongside ifDescr.
"""
from alembic import op
import sqlalchemy as sa

revision = "856a4b0ddefc"
down_revision = "602468fddd33"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_snmp_interfaces", sa.Column("if_name", sa.String(length=255), nullable=True))
    op.add_column("asset_snmp_interfaces", sa.Column("if_alias", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("asset_snmp_interfaces", "if_alias")
    op.drop_column("asset_snmp_interfaces", "if_name")
