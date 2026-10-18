"""
Compliance with standards (PCI DSS, ISO/IEC 27001, NIST SP 800-53, or the organisation's own, e.g. national
requirements): each requirement of a standard is evidenced by the audit checks of its security domains
(app/modules/compliance/domains.py), named topics or named checks, and scored from the latest audit of
every asset; a requirement no check covers is assessed by hand.

  ComplianceStandard       a standard; the built-in ones come from app/modules/compliance/standards/*.json
                           and are kept in step with those files, the organisation can add its own
  ComplianceRequirement    one requirement, with its mapping {"all", "domains", "topics", "checks"}
  ComplianceCheckDomains   an administrator's correction of the domains of one check
  ComplianceAssessment     a requirement assessed by hand, for every asset or one asset group, until a date
"""
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from app.core.database import Base

ASSESSMENT_STATUSES = ("met", "partial", "not_met", "not_applicable")


class ComplianceStandard(Base):
    __tablename__ = "compliance_standards"

    id = Column(Integer, primary_key=True)
    key = Column(String(60), nullable=False, unique=True)          # "pci-dss-4.0", "custom-3"
    name = Column(String(120), nullable=False)
    name_fa = Column(String(160), nullable=True)
    version = Column(String(40), nullable=True)
    description = Column(Text, nullable=True)
    description_fa = Column(Text, nullable=True)
    builtin = Column(Boolean, nullable=False, default=False, server_default="false")
    enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class ComplianceRequirement(Base):
    __tablename__ = "compliance_requirements"
    __table_args__ = (UniqueConstraint("standard_id", "ref", name="uq_compliance_requirement_ref"),)

    id = Column(Integer, primary_key=True)
    standard_id = Column(Integer, ForeignKey("compliance_standards.id", ondelete="CASCADE"), nullable=False,
                         index=True)
    ref = Column(String(40), nullable=False)                       # "8.3.6", "A.8.15", "AC-7"
    section = Column(String(40), nullable=True)                    # groups requirements on the page
    title = Column(String(500), nullable=False)
    title_fa = Column(String(500), nullable=True)
    mapping = Column(JSON, nullable=False, default=dict)           # see domains.requirement_matches
    position = Column(Integer, nullable=False, default=0)


class ComplianceSection(Base):
    """A heading that groups a standard's requirements ("8 Identify users and authenticate access")."""
    __tablename__ = "compliance_sections"
    __table_args__ = (UniqueConstraint("standard_id", "ref", name="uq_compliance_section_ref"),)

    id = Column(Integer, primary_key=True)
    standard_id = Column(Integer, ForeignKey("compliance_standards.id", ondelete="CASCADE"), nullable=False,
                         index=True)
    ref = Column(String(40), nullable=False)
    title = Column(String(300), nullable=False)
    title_fa = Column(String(300), nullable=True)
    position = Column(Integer, nullable=False, default=0)


class ComplianceCheckDomains(Base):
    __tablename__ = "compliance_check_domains"
    __table_args__ = (UniqueConstraint("benchmark", "check_number", name="uq_compliance_check_domains"),)

    id = Column(Integer, primary_key=True)
    benchmark = Column(String(40), nullable=False)                 # AuditSession.device_type value
    check_number = Column(String(50), nullable=False)
    domains = Column(JSON, nullable=False, default=list)           # [] = no domain
    updated_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ComplianceAssessment(Base):
    __tablename__ = "compliance_assessments"

    id = Column(Integer, primary_key=True)
    requirement_id = Column(Integer, ForeignKey("compliance_requirements.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=True)  # None: all
    status = Column(String(20), nullable=False)                    # ASSESSMENT_STATUSES
    note = Column(Text, nullable=False)
    valid_until = Column(DateTime, nullable=True)
    assessed_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assessed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
