"""Compliance with standards: standards, sections, requirements, check domains, assessments

Revision ID: b5d7f9a1c3e6
Revises: a4c6e8f0b2d5
Create Date: 2026-10-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b5d7f9a1c3e6"
down_revision: Union[str, Sequence[str], None] = "a4c6e8f0b2d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_standards",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(60), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("name_fa", sa.String(160), nullable=True),
        sa.Column("version", sa.String(40), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("description_fa", sa.Text(), nullable=True),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "compliance_sections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("standard_id", sa.Integer(), sa.ForeignKey("compliance_standards.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("ref", sa.String(40), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("title_fa", sa.String(300), nullable=True),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("standard_id", "ref", name="uq_compliance_section_ref"),
    )
    op.create_index("ix_compliance_sections_standard_id", "compliance_sections", ["standard_id"])
    op.create_table(
        "compliance_requirements",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("standard_id", sa.Integer(), sa.ForeignKey("compliance_standards.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("ref", sa.String(40), nullable=False),
        sa.Column("section", sa.String(40), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("title_fa", sa.String(500), nullable=True),
        sa.Column("mapping", sa.JSON(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("standard_id", "ref", name="uq_compliance_requirement_ref"),
    )
    op.create_index("ix_compliance_requirements_standard_id", "compliance_requirements", ["standard_id"])
    op.create_table(
        "compliance_check_domains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("benchmark", sa.String(40), nullable=False),
        sa.Column("check_number", sa.String(50), nullable=False),
        sa.Column("domains", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("benchmark", "check_number", name="uq_compliance_check_domains"),
    )
    op.create_table(
        "compliance_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("requirement_id", sa.Integer(),
                  sa.ForeignKey("compliance_requirements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("valid_until", sa.DateTime(), nullable=True),
        sa.Column("assessed_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("assessed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_compliance_assessments_requirement_id", "compliance_assessments", ["requirement_id"])


def downgrade() -> None:
    op.drop_table("compliance_assessments")
    op.drop_table("compliance_check_domains")
    op.drop_table("compliance_requirements")
    op.drop_table("compliance_sections")
    op.drop_table("compliance_standards")
