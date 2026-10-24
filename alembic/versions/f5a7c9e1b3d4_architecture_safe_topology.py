"""Architecture Validation checks the topology against Cisco SAFE

Revision ID: f5a7c9e1b3d4
Revises: e3b5d7f9a1c2
Create Date: 2026-10-24

- architecture_findings.evidence: what the topology shows for a finding (the unfiltered path, the link,
  the assets cut off);
- risk_zones.place: the zone's Cisco SAFE place in the network, when chosen (else read from its name);
- the findings of the retired checks (AV-001 to AV-024: inventory, backups and audits, which other
  modules cover) are removed; Remediation closes their items as "check retired".
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f5a7c9e1b3d4"
down_revision: Union[str, Sequence[str], None] = "e3b5d7f9a1c2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

RETIRED = ("AV-001", "AV-002", "AV-003", "AV-010", "AV-011", "AV-012", "AV-020", "AV-021", "AV-022",
           "AV-023", "AV-024")


def upgrade() -> None:
    op.add_column("architecture_findings", sa.Column("evidence", sa.Text(), nullable=True))
    op.add_column("risk_zones", sa.Column("place", sa.String(length=20), nullable=True))
    op.get_bind().execute(sa.text("DELETE FROM architecture_findings WHERE rule_code IN :codes")
                          .bindparams(sa.bindparam("codes", expanding=True)), {"codes": list(RETIRED)})


def downgrade() -> None:
    op.drop_column("risk_zones", "place")
    op.drop_column("architecture_findings", "evidence")
