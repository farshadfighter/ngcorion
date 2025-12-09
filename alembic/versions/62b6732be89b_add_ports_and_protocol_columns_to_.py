"""add ports and protocol columns to discovery_scans

Revision ID: 62b6732be89b
Revises: e4de134c385b
Create Date: 2025-12-09 14:56:22.391127

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '62b6732be89b'
down_revision: Union[str, Sequence[str], None] = 'e4de134c385b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add ports column
    op.add_column(
        'discovery_scans',
        sa.Column(
            'ports',
            sa.String(255),
            nullable=True,
            comment="Ports to scan (e.g., '80,443,8080' or '1-1000' or 'top1000')"
        )
    )

    # Add protocol column
    op.add_column(
        'discovery_scans',
        sa.Column(
            'protocol',
            sa.String(20),
            nullable=True,
            server_default='TCP',
            comment="Protocol to scan: TCP, UDP, or BOTH"
        )
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Remove protocol column
    op.drop_column('discovery_scans', 'protocol')

    # Remove ports column
    op.drop_column('discovery_scans', 'ports')
