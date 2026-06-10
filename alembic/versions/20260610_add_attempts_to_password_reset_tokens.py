"""add attempts to password_reset_tokens

Revision ID: 20260610_pwd_attempts
Revises: 20260609_pwd_reset
Create Date: 2026-06-10

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '20260610_pwd_attempts'
down_revision: Union[str, Sequence[str], None] = '20260609_pwd_reset'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'password_reset_tokens',
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0',
                  comment='Failed verification attempts; OTP invalidated past the limit'),
    )


def downgrade() -> None:
    op.drop_column('password_reset_tokens', 'attempts')
