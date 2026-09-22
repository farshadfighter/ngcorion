"""add cve records table

Revision ID: a8d5132ede7a
Revises: b7c14e29f0a3
Create Date: 2026-09-20 07:45:47.636735

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a8d5132ede7a'
down_revision: Union[str, Sequence[str], None] = 'b7c14e29f0a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'cve_records',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('vendor', sa.String(length=100), nullable=False),
        sa.Column('product', sa.String(length=100), nullable=False),
        sa.Column('product_keyword', sa.String(length=100), nullable=False),
        sa.Column('affected_version_min', sa.String(length=50), nullable=True),
        sa.Column('affected_version_max', sa.String(length=50), nullable=True),
        sa.Column('fixed_version', sa.String(length=50), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('reference_url', sa.String(length=500), nullable=True),
        sa.Column('published_date', sa.DateTime(), nullable=True),
        sa.Column('source', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'cve_id', 'product_keyword', 'affected_version_min', 'affected_version_max',
            name='uq_cve_records_branch',
        ),
    )
    op.create_index(op.f('ix_cve_records_id'), 'cve_records', ['id'], unique=False)
    op.create_index(op.f('ix_cve_records_cve_id'), 'cve_records', ['cve_id'], unique=False)
    op.create_index(op.f('ix_cve_records_product_keyword'), 'cve_records', ['product_keyword'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_cve_records_product_keyword'), table_name='cve_records')
    op.drop_index(op.f('ix_cve_records_cve_id'), table_name='cve_records')
    op.drop_index(op.f('ix_cve_records_id'), table_name='cve_records')
    op.drop_table('cve_records')
