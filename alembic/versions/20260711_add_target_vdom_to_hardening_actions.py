"""add target_vdom to hardening_actions

Revision ID: 20260711_hvdom
Revises: 20260709_widen
Create Date: 2026-07-11

Adds a nullable ``target_vdom`` column to ``hardening_actions`` so FortiGate
fixes record which VDOM context they were applied in ("global"/"root"/<name>).
NULL for flat (non-VDOM) devices and every other device type, so the column is
safe for all modules that share this table.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '20260711_hvdom'
down_revision: Union[str, Sequence[str], None] = '20260709_widen'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'hardening_actions',
        sa.Column('target_vdom', sa.String(length=80), nullable=True,
                  comment='FortiGate VDOM context the fix was applied in '
                          '(global/root/<name>); NULL for non-VDOM devices '
                          'and other device types'),
    )


def downgrade() -> None:
    op.drop_column('hardening_actions', 'target_vdom')
