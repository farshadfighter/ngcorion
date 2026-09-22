"""add hosted_on_asset_id and hosted_vlan to asset_inventory

Revision ID: 1fa08af4f364
Revises: b7c14e29f0a3
Create Date: 2026-09-20 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1fa08af4f364'
down_revision: Union[str, Sequence[str], None] = 'b7c14e29f0a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('asset_inventory', sa.Column('hosted_on_asset_id', sa.Integer(), nullable=True))
    op.add_column('asset_inventory', sa.Column('hosted_vlan', sa.String(length=20), nullable=True))
    op.create_index(
        op.f('ix_asset_inventory_hosted_on_asset_id'), 'asset_inventory', ['hosted_on_asset_id'], unique=False
    )
    op.create_foreign_key(
        'fk_asset_inventory_hosted_on_asset_id',
        'asset_inventory', 'asset_inventory',
        ['hosted_on_asset_id'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_asset_inventory_hosted_on_asset_id', 'asset_inventory', type_='foreignkey')
    op.drop_index(op.f('ix_asset_inventory_hosted_on_asset_id'), table_name='asset_inventory')
    op.drop_column('asset_inventory', 'hosted_vlan')
    op.drop_column('asset_inventory', 'hosted_on_asset_id')
