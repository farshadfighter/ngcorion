"""add sub_device_type to audit_sessions

Revision ID: 414943cd5479
Revises: 83d06c423132
Create Date: 2026-05-30
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '414943cd5479'
down_revision: Union[str, Sequence[str], None] = '83d06c423132'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'audit_sessions',
        sa.Column('sub_device_type', sa.String(50), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('audit_sessions', 'sub_device_type')
