"""add_job_name_to_audit_sessions

Revision ID: a1b2c3d4e5f6
Revises: 13e012e77576
Create Date: 2026-02-17 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '13e012e77576'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add job_name column to audit_sessions."""
    op.add_column('audit_sessions', sa.Column('job_name', sa.String(200), nullable=True))


def downgrade() -> None:
    """Remove job_name column from audit_sessions."""
    op.drop_column('audit_sessions', 'job_name')
