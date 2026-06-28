"""add vdom to audit_results

Revision ID: 20260628_vdom
Revises: 20260610_pwd_attempts
Create Date: 2026-06-28

Adds a nullable ``vdom`` column to ``audit_results`` so FortiGate multi-VDOM
audits can record which virtual domain each finding was evaluated in
("global"/"root" for global-scoped controls, the VDOM name for per-VDOM
controls). NULL for non-VDOM devices and non-FortiGate device types, so the
column is safe for every other module that shares this table.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '20260628_vdom'
down_revision: Union[str, Sequence[str], None] = '20260610_pwd_attempts'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'audit_results',
        sa.Column('vdom', sa.String(length=80), nullable=True,
                  comment='FortiGate VDOM context for this finding (global/root/<name>); '
                          'NULL for non-VDOM devices and other device types'),
    )


def downgrade() -> None:
    op.drop_column('audit_results', 'vdom')
