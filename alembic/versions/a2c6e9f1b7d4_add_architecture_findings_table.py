"""add architecture_findings table

Revision ID: a2c6e9f1b7d4
Revises: f4a7c3e8d1b5
Create Date: 2026-09-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a2c6e9f1b7d4'
down_revision: Union[str, Sequence[str], None] = 'f4a7c3e8d1b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'architecture_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_code', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='medium'),
        sa.Column('category', sa.String(length=50), nullable=True),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('asset_name', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='open'),
        sa.Column('ignored_reason', sa.Text(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['asset_inventory.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_architecture_findings_id'), 'architecture_findings', ['id'], unique=False)
    op.create_index(op.f('ix_architecture_findings_rule_code'), 'architecture_findings', ['rule_code'], unique=False)
    op.create_index(op.f('ix_architecture_findings_asset_id'), 'architecture_findings', ['asset_id'], unique=False)
    op.create_index(op.f('ix_architecture_findings_status'), 'architecture_findings', ['status'], unique=False)
    op.create_index(op.f('ix_architecture_findings_created_at'), 'architecture_findings', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_architecture_findings_created_at'), table_name='architecture_findings')
    op.drop_index(op.f('ix_architecture_findings_status'), table_name='architecture_findings')
    op.drop_index(op.f('ix_architecture_findings_asset_id'), table_name='architecture_findings')
    op.drop_index(op.f('ix_architecture_findings_rule_code'), table_name='architecture_findings')
    op.drop_index(op.f('ix_architecture_findings_id'), table_name='architecture_findings')
    op.drop_table('architecture_findings')
